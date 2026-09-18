// Package client is addy's Go reference client.
//
// It exists because M1's gate needs it: "a device mints an account from
// nothing, a second pairs and verifies emoji, a third is refused" cannot be
// demonstrated without a client, and `addy selftest` and the compose
// integration test both need one. The design's original milestone table did not
// fund it until M3, which was an error -- M1's own end condition requires it.
//
// It is also the second implementation of every client-side rule in
// internal/protocol, which is worth more than it costs: a rule that only the
// package that defines it obeys is a rule nobody has checked.
package client

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/opsmaxx/addy/internal/protocol"
)

// Client talks to one instance as one device.
type Client struct {
	BaseURL string
	HTTP    *http.Client

	Account protocol.AccountID
	Device  *protocol.DeviceKeys

	// spki is the TOFU pin of the instance's TLS key, which every login
	// signature covers. Without it a login captured from one instance replays
	// against another serving the same account.
	spki  []byte
	token string
}

// New builds a client. insecure skips certificate verification, which dev mode
// needs and production must not use -- it is a separate flag rather than a
// fallback so it cannot be reached by accident.
func New(baseURL string, insecure bool) *Client {
	tr := &http.Transport{}
	if insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &Client{
		BaseURL: baseURL,
		HTTP:    &http.Client{Timeout: 45 * time.Second, Transport: tr},
	}
}

// Pin records the instance's TLS key, which is what the addy:// join string
// carries and what every login signature binds to.
func (c *Client) Pin() error {
	req, err := http.NewRequest(http.MethodGet, c.BaseURL+"/v1/meta", nil)
	if err != nil {
		return err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("client: reaching %s: %w", c.BaseURL, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return errors.New("client: the instance presented no certificate")
	}
	c.spki = spkiHash(resp.TLS.PeerCertificates[0])
	return nil
}

func spkiHash(cert *x509.Certificate) []byte {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return sum[:]
}

// Register mints an account offline and then tells the server about it.
//
// In that order, and the order is the point: the server is handed a public key
// and a signed entry it cannot forge, after the fact. It validates nothing
// about who you are.
func (c *Client) Register(label, invite string) (*protocol.Account, error) {
	a, err := protocol.NewAccount(label)
	if err != nil {
		return nil, err
	}
	wire, err := a.Genesis.Wire()
	if err != nil {
		return nil, err
	}

	body, _ := json.Marshal(map[string]string{
		"account":       a.Root.AccountID.String(),
		"root_sign_pub": hex.EncodeToString(a.Root.Sign.Public().(ed25519.PublicKey)),
		"invite":        invite,
		"genesis":       base64.StdEncoding.EncodeToString(wire),
		"escrow":        base64.StdEncoding.EncodeToString(a.Escrow),
	})

	resp, err := c.HTTP.Post(c.BaseURL+"/v1/account", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("client: registering: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("client: registering: %s: %s", resp.Status, readErr(resp.Body))
	}

	c.Account = a.Root.AccountID
	c.Device = a.Device
	return a, nil
}

// Login proves this device holds its signing key.
func (c *Client) Login() error {
	if c.Device == nil {
		return errors.New("client: no device keys")
	}
	if c.spki == nil {
		if err := c.Pin(); err != nil {
			return err
		}
	}

	devicePub := c.Device.Sign.Public().(ed25519.PublicKey)

	body, _ := json.Marshal(map[string]string{
		"account": c.Account.String(),
		"device":  hex.EncodeToString(devicePub),
	})
	resp, err := c.HTTP.Post(c.BaseURL+"/v1/auth/challenge", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("client: requesting a challenge: %w", err)
	}
	defer resp.Body.Close()
	var ch struct {
		Nonce string `json:"nonce"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ch); err != nil {
		return fmt.Errorf("client: reading the challenge: %w", err)
	}

	deviceNonce, err := protocol.Nonce()
	if err != nil {
		return err
	}
	serverNonce, err := hex.DecodeString(ch.Nonce)
	if err != nil {
		return fmt.Errorf("client: the challenge is not hex: %w", err)
	}

	login := protocol.Login{
		AccountID:   c.Account,
		DeviceNonce: deviceNonce,
		ServerNonce: serverNonce,
		ServerSPKI:  c.spki,
		TS:          uint64(time.Now().UnixMilli()),
	}
	sig, err := protocol.Sign(c.Device.Sign, login)
	if err != nil {
		return err
	}

	body, _ = json.Marshal(map[string]any{
		"account":      c.Account.String(),
		"device":       hex.EncodeToString(devicePub),
		"device_nonce": hex.EncodeToString(deviceNonce),
		"server_nonce": ch.Nonce,
		"server_spki":  hex.EncodeToString(c.spki),
		"ts":           login.TS,
		"signature":    hex.EncodeToString(sig),
	})
	resp2, err := c.HTTP.Post(c.BaseURL+"/v1/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("client: logging in: %w", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		return fmt.Errorf("client: logging in: %s: %s", resp2.Status, readErr(resp2.Body))
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&out); err != nil {
		return err
	}
	c.token = out.Token
	return nil
}

// do performs an authorised request. Every one carries a signature over its
// method, path and body, so an authorization for a GET cannot be replayed as
// the DELETE the server would rather have had.
func (c *Client) do(method, path string, payload any) (*http.Response, error) {
	// Before anything is marshalled or signed. A client used out of order --
	// GetObject before Login, most plausibly in a retry path that lost its
	// session -- otherwise dereferences a nil device key and panics, which in
	// a sidecar takes the process down and, through the parent's parser,
	// whatever else was in flight on the same pipe. An error is what the
	// caller can act on.
	if c.Device == nil {
		return nil, errors.New("client: no device key; register or restore an account first")
	}
	if c.token == "" {
		return nil, errors.New("client: not logged in")
	}

	var body []byte
	if payload != nil {
		var err error
		if body, err = json.Marshal(payload); err != nil {
			return nil, err
		}
	}

	nonce, err := protocol.Nonce()
	if err != nil {
		return nil, err
	}
	authz := protocol.Authz{
		AccountID:   c.Account,
		DeviceNonce: nonce,
		Method:      method,
		Path:        pathOnly(path),
		BodyHash:    protocol.HashBody(body),
	}
	sig, err := protocol.Sign(c.Device.Sign, authz)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(method, c.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("X-Addy-Nonce", hex.EncodeToString(nonce))
	req.Header.Set("X-Addy-Signature", hex.EncodeToString(sig))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.HTTP.Do(req)
}

func pathOnly(p string) string {
	for i := 0; i < len(p); i++ {
		if p[i] == '?' {
			return p[:i]
		}
	}
	return p
}

// Roster fetches and VERIFIES the chain.
//
// Verification takes the root key and epoch 1's key from the caller, never from
// the server. A chain verified against a key the server supplied is not
// verified, and that is the single most important line in this file.
func (c *Client) Roster(rootSignPub, epoch1Sign ed25519.PublicKey, pin *protocol.Pin) (*protocol.Verified, error) {
	resp, err := c.do(http.MethodGet, "/v1/roster", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("client: fetching the roster: %s: %s", resp.Status, readErr(resp.Body))
	}
	var out struct {
		Chain string `json:"chain"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	chain, err := base64.StdEncoding.DecodeString(out.Chain)
	if err != nil {
		return nil, fmt.Errorf("client: the chain is not base64: %w", err)
	}
	return protocol.VerifyChain(chain, c.Account, rootSignPub, epoch1Sign, pin)
}

// AppendRoster publishes one entry.
func (c *Client) AppendRoster(e protocol.Entry) error {
	wire, err := e.Wire()
	if err != nil {
		return err
	}
	resp, err := c.do(http.MethodPost, "/v1/roster", map[string]any{
		"seq":   e.Seq,
		"entry": base64.StdEncoding.EncodeToString(wire),
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("client: appending to the roster: %s: %s", resp.Status, readErr(resp.Body))
	}
	return nil
}

// SendFrame publishes an opaque signalling frame to one peer device.
//
// A frame names the device it is for. There is no "broadcast" and no way to ask
// for somebody else's mailbox, which is what stops one device draining
// another's.
func (c *Client) SendFrame(toDevice []byte, frame []byte) error {
	resp, err := c.do(http.MethodGet, "/v1/signal?to="+hex.EncodeToString(toDevice), map[string]string{
		"frame": base64.StdEncoding.EncodeToString(frame),
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("client: sending a frame: %s: %s", resp.Status, readErr(resp.Body))
	}
	return nil
}

// NextFrame waits for one. A 204 means nothing arrived, which is not a failure.
func (c *Client) NextFrame() ([]byte, error) {
	resp, err := c.do(http.MethodGet, "/v1/signal", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("client: waiting for a frame: %s: %s", resp.Status, readErr(resp.Body))
	}
	var out struct {
		Frame string `json:"frame"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(out.Frame)
}

func readErr(r io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(r, 4<<10))
	return string(bytes.TrimSpace(b))
}

// The pairing rendezvous. A joining device has no session and does not know the
// account id, so these do not go through do() and carry no authorization.

// SendPairFrame publishes into a pairing room.
func (c *Client) SendPairFrame(role string, pairingID []byte, frame []byte) error {
	body, _ := json.Marshal(map[string]string{
		"frame": base64.StdEncoding.EncodeToString(frame),
	})
	url := c.BaseURL + "/v1/pair/" + hex.EncodeToString(pairingID) + "?as=" + role
	resp, err := c.HTTP.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("client: sending a pairing frame: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("client: sending a pairing frame: %s: %s", resp.Status, readErr(resp.Body))
	}
	return nil
}

// NextPairFrame waits for one.
func (c *Client) NextPairFrame(role string, pairingID []byte) ([]byte, error) {
	url := c.BaseURL + "/v1/pair/" + hex.EncodeToString(pairingID) + "?as=" + role
	resp, err := c.HTTP.Get(url)
	if err != nil {
		return nil, fmt.Errorf("client: waiting for a pairing frame: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("client: waiting for a pairing frame: %s: %s", resp.Status, readErr(resp.Body))
	}
	var out struct {
		Frame string `json:"frame"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(out.Frame)
}

// CapturedRequestForTest builds an authorised request without sending it, so a
// test can replay the exact bytes that went out.
//
// Exported for tests rather than reconstructed in them: a test that builds its
// own approximation of an authorised request is testing its approximation.
func (c *Client) CapturedRequestForTest(method, path string) (*http.Request, error) {
	nonce, err := protocol.Nonce()
	if err != nil {
		return nil, err
	}
	authz := protocol.Authz{
		AccountID:   c.Account,
		DeviceNonce: nonce,
		Method:      method,
		Path:        pathOnly(path),
		BodyHash:    protocol.HashBody(nil),
	}
	sig, err := protocol.Sign(c.Device.Sign, authz)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(method, c.BaseURL+path, bytes.NewReader(nil))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("X-Addy-Nonce", hex.EncodeToString(nonce))
	req.Header.Set("X-Addy-Signature", hex.EncodeToString(sig))
	return req, nil
}

// Notification mirrors the server's change pointer.
type Notification struct {
	Collection string `json:"collection"`
	Epoch      uint64 `json:"epoch"`
	Revision   uint64 `json:"revision"`
	Actor      string `json:"actor"`
	Resync     bool   `json:"resync,omitempty"`
}

// PutObject writes a sealed object.
func (c *Client) PutObject(name string, epoch, counter uint64, body []byte, ifMatch string) (string, error) {
	nonce, err := protocol.Nonce()
	if err != nil {
		return "", err
	}
	payload, _ := json.Marshal(map[string]any{
		"epoch": epoch, "counter": counter,
		"body": base64.StdEncoding.EncodeToString(body),
	})
	authz := protocol.Authz{
		AccountID: c.Account, DeviceNonce: nonce,
		Method: http.MethodPut, Path: "/v1/obj/" + name,
		BodyHash: protocol.HashBody(payload),
	}
	sig, err := protocol.Sign(c.Device.Sign, authz)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest(http.MethodPut, c.BaseURL+"/v1/obj/"+name, bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("X-Addy-Nonce", hex.EncodeToString(nonce))
	req.Header.Set("X-Addy-Signature", hex.EncodeToString(sig))
	req.Header.Set("Content-Type", "application/json")
	if ifMatch != "" {
		req.Header.Set("If-Match", ifMatch)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return "", fmt.Errorf("client: writing %s: %s: %s", name, resp.Status, readErr(resp.Body))
	}
	return resp.Header.Get("ETag"), nil
}

// StoredObject is one sealed object as the server returned it. The body is
// still sealed: the client decides what it is, and this layer never does.
type StoredObject struct {
	Body    []byte
	Counter uint64
	ETag    string
}

// GetObject reads one sealed object back.
//
// The name and epoch are all the caller supplies. WHICH ACCOUNT is not a
// parameter here and is not one on the wire either -- the server takes it from
// the session. That is the only reason two accounts cannot read each other's
// objects, and internal/api/isolation_test.go is where it is proved rather
// than assumed.
func (c *Client) GetObject(name string, epoch uint64) (*StoredObject, error) {
	resp, err := c.do(http.MethodGet, fmt.Sprintf("/v1/obj/%s?epoch=%d", name, epoch), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("client: reading %s: %s: %s", name, resp.Status, readErr(resp.Body))
	}
	var out struct {
		Body    string `json:"body"`
		Counter uint64 `json:"counter"`
		ETag    string `json:"etag"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	body, err := base64.StdEncoding.DecodeString(out.Body)
	if err != nil {
		return nil, fmt.Errorf("client: %s came back with a body that is not base64", name)
	}
	return &StoredObject{Body: body, Counter: out.Counter, ETag: out.ETag}, nil
}

// Changes waits for change pointers.
//
// The server already drops this device's own writes, so what comes back is
// other devices' changes. A nil slice means nothing arrived, which is not a
// failure -- a client that treats a quiet account as an error backs off from a
// working one.
func (c *Client) Changes() ([]Notification, error) {
	resp, err := c.do(http.MethodGet, "/v1/changes", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("client: waiting for changes: %s: %s", resp.Status, readErr(resp.Body))
	}
	var out struct {
		Notifications []Notification `json:"notifications"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Notifications, nil
}

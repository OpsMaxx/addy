package api_test

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/opsmaxx/addy/internal/client"
	"github.com/opsmaxx/addy/internal/protocol"
)

// nextEntry builds the entry after prev, signed the way signer says: by the
// epoch key, as a paired device adds or revokes, or by the root key, as a
// device recovering from the phrase adds itself.
func nextEntry(t *testing.T, acct *protocol.Account, prev protocol.Entry, op protocol.Op, signer protocol.Signer, dev *protocol.DeviceKeys) protocol.Entry {
	t.Helper()
	head, err := prev.Hash()
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := protocol.Nonce()
	if err != nil {
		t.Fatal(err)
	}
	pubSign := dev.Sign.Public().(ed25519.PublicKey)
	e := protocol.Entry{
		AccountID: acct.Root.AccountID, Epoch: 1, Seq: prev.Seq + 1, PrevHash: head,
		Op: op, Signer: signer, Nonce: nonce,
		PubSign: pubSign, PubEnc: dev.Enc.PublicKey().Bytes(), TS: prev.TS + 1,
	}
	if op == protocol.OpAdd {
		if e.LabelCT, err = protocol.SealLabel("brave-pylon-07", acct.Root.AccountID, 1, pubSign, acct.Epoch.Profile); err != nil {
			t.Fatal(err)
		}
	}
	body, err := e.Encode()
	if err != nil {
		t.Fatal(err)
	}
	key := acct.Epoch.Sign
	if signer == protocol.SignerRK {
		key = acct.Root.Sign
	}
	e.Sig = ed25519.Sign(key, body)
	return e
}

// addedDevice registers an account on a, appends an add for a fresh device,
// and returns that device logged in.
func addedDevice(t *testing.T, srv string, a *client.Client, acct *protocol.Account) (*client.Client, protocol.Entry) {
	t.Helper()
	dev := mustDevice(t)
	add := nextEntry(t, acct, acct.Genesis, protocol.OpAdd, protocol.SignerAK, dev)
	if err := a.AppendRoster(add); err != nil {
		t.Fatalf("adding a second device: %v", err)
	}
	b := client.New(srv, true)
	b.Account, b.Device = acct.Root.AccountID, dev
	if err := b.Login(); err != nil {
		t.Fatalf("the added device could not log in: %v", err)
	}
	return b, add
}

// status makes a signed request and returns its status and error message.
func status(t *testing.T, c *client.Client, method, path string, payload any) (int, string) {
	t.Helper()
	resp, err := c.RawRequest(method, path, payload)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body struct {
		Error string `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body.Error
}

// A KEY NOBODY ADDED GETS NOTHING BUT THE RECOVERY CALLS.
//
// It used to get everything: any key that signed a login got a full session,
// which could write objects, append to the roster and join the overlay.
func TestAStrangersKeyReachesOnlyRecovery(t *testing.T) {
	srv, db := instance(t)
	a := client.New(srv.URL, true)
	acct, err := a.Register("quiet-otter-41", invite(t, db))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Login(); err != nil {
		t.Fatal(err)
	}

	stranger := client.New(srv.URL, true)
	stranger.Account, stranger.Device = acct.Root.AccountID, mustDevice(t)
	if err := stranger.Login(); err != nil {
		t.Fatalf("a stranger's login should be limited, not refused (recovery needs it): %v", err)
	}

	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/v1/obj/servers?epoch=1"},
		{http.MethodPut, "/v1/obj/servers"},
		{http.MethodPost, "/v1/overlay/join"},
		{http.MethodGet, "/v1/changes"},
		{http.MethodGet, "/v1/turn"},
	} {
		code, msg := status(t, stranger, c.method, c.path, map[string]any{})
		if code != http.StatusUnauthorized || msg != "this device is not on its sync group's roster" {
			t.Errorf("%s %s by a stranger = %d %q, want 401", c.method, c.path, code, msg)
		}
	}
	if _, err := stranger.PutObject("servers", 1, 1, []byte("x"), ""); err == nil {
		t.Error("a stranger wrote an object")
	}

	// It may read what a recovery reads.
	if code, _ := status(t, stranger, http.MethodGet, "/v1/roster", nil); code != http.StatusOK {
		t.Errorf("a limited session could not read the roster: %d", code)
	}

	// And it may append nothing but a root-signed add of itself, which it
	// cannot produce without the phrase. An epoch-key-shaped entry signed by
	// its own key is the forgery this refuses.
	forged := protocol.Account{Root: acct.Root, Epoch: acct.Epoch, Genesis: acct.Genesis}
	forged.Epoch = &protocol.EpochKeys{Sign: stranger.Device.Sign, Profile: acct.Epoch.Profile}
	if err := stranger.AppendRoster(nextEntry(t, &forged, acct.Genesis, protocol.OpAdd, protocol.SignerAK, stranger.Device)); err == nil ||
		!strings.Contains(err.Error(), "403") {
		t.Errorf("a stranger appended itself to the roster: %v", err)
	}

	// The same answer for an account that does not exist, so the login is no
	// oracle for which ids do.
	nobody := client.New(srv.URL, true)
	nobody.Device = mustDevice(t)
	nobody.Account = protocol.DeriveAccountID(mustDevice(t).Sign.Public().(ed25519.PublicKey))
	if err := nobody.Login(); err != nil {
		t.Errorf("a login to an absent account answered differently: %v", err)
	}
}

// A REVOKE ENDS THE DEVICE'S SESSIONS, AND LOGGING IN AGAIN GETS IT ONLY THE
// ROSTER -- which is how it learns it was revoked and wipes itself.
func TestARevokedDeviceLosesItsSessionAndCannotLogIn(t *testing.T) {
	srv, db := instance(t)
	a := client.New(srv.URL, true)
	acct, err := a.Register("quiet-otter-41", invite(t, db))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Login(); err != nil {
		t.Fatal(err)
	}
	b, add := addedDevice(t, srv.URL, a, acct)
	if _, err := b.PutObject("servers", 1, 1, []byte("sealed"), ""); err != nil {
		t.Fatalf("an added device could not write: %v", err)
	}

	if err := a.AppendRoster(nextEntry(t, acct, add, protocol.OpRevoke, protocol.SignerAK, b.Device)); err != nil {
		t.Fatalf("revoking: %v", err)
	}

	// Its live session is over -- and NOT with "unknown or expired session",
	// which a client answers by logging in again.
	code, msg := status(t, b, http.MethodGet, "/v1/obj/servers?epoch=1", nil)
	if code != http.StatusUnauthorized || msg != "this device has been removed from its sync group" {
		t.Errorf("the revoked device's session answered %d %q", code, msg)
	}
	if code, _ := status(t, b, http.MethodGet, "/v1/roster", nil); code != http.StatusOK {
		t.Errorf("the revoked device cannot read the roster that tells it to wipe: %d", code)
	}
	// A fresh login is no way round it.
	if err := b.Login(); err != nil {
		t.Fatalf("a revoked device must still log in to learn it was revoked: %v", err)
	}
	for _, path := range []string{"/v1/obj/servers?epoch=1", "/v1/obj/escrow?epoch=1"} {
		if code, msg := status(t, b, http.MethodGet, path, nil); code != http.StatusUnauthorized ||
			msg != "this device has been removed from its sync group" {
			t.Errorf("GET %s after a fresh login = %d %q", path, code, msg)
		}
	}
	if code, _ := status(t, b, http.MethodGet, "/v1/roster", nil); code != http.StatusOK {
		t.Errorf("after a fresh login the revoked device cannot read the roster: %d", code)
	}
	// The device that revoked it is untouched.
	if _, err := a.GetObject("servers", 1); err != nil {
		t.Errorf("the revoking device lost access: %v", err)
	}
}

// RECOVERY STILL WORKS: fresh keys log in limited, read what they need, add
// themselves with the root key, and the same session is then a member's.
func TestARecoveringDeviceAddsItselfWithTheRootKey(t *testing.T) {
	srv, db := instance(t)
	a := client.New(srv.URL, true)
	acct, err := a.Register("quiet-otter-41", invite(t, db))
	if err != nil {
		t.Fatal(err)
	}

	r := client.New(srv.URL, true)
	r.Account, r.Device = acct.Root.AccountID, mustDevice(t)
	if err := r.Login(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.GetObject("escrow", 1); err != nil {
		t.Fatalf("a recovering device could not read the escrow: %v", err)
	}
	v, err := r.Roster(acct.Root.Sign.Public().(ed25519.PublicKey), acct.Epoch.Sign.Public().(ed25519.PublicKey), nil)
	if err != nil || len(v.Devices) != 1 {
		t.Fatalf("a recovering device could not read the roster: %v", err)
	}

	// A root-signed add of somebody ELSE is refused: the exception is for
	// adding yourself.
	if err := r.AppendRoster(nextEntry(t, acct, acct.Genesis, protocol.OpAdd, protocol.SignerRK, mustDevice(t))); err == nil {
		t.Fatal("a limited session added a device other than itself")
	}
	if err := r.AppendRoster(nextEntry(t, acct, acct.Genesis, protocol.OpAdd, protocol.SignerRK, r.Device)); err != nil {
		t.Fatalf("the root-signed self-add was refused: %v", err)
	}
	if _, err := r.PutObject("servers", 1, 1, []byte("sealed"), ""); err != nil {
		t.Errorf("after adding itself the device still could not write: %v", err)
	}
}

// AN ENTRY THAT DOES NOT EXTEND THE CHAIN IS REFUSED, rather than stored for
// every device to fail on.
func TestARosterAppendMustExtendTheChain(t *testing.T) {
	srv, db := instance(t)
	a := client.New(srv.URL, true)
	acct, err := a.Register("quiet-otter-41", invite(t, db))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Login(); err != nil {
		t.Fatal(err)
	}
	// A revoke of a device nobody added.
	bad := nextEntry(t, acct, acct.Genesis, protocol.OpRevoke, protocol.SignerAK, mustDevice(t))
	if err := a.AppendRoster(bad); err == nil || !strings.Contains(err.Error(), "400") {
		t.Errorf("a revoke of an absent device was stored: %v", err)
	}
}

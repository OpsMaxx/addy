package api_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/opsmaxx/addy/internal/client"
	"github.com/opsmaxx/addy/internal/protocol"
)

// junkSigned is a well-formed add whose signature is 64 bytes of nothing.
func junkSigned(t *testing.T, acct *protocol.Account) (protocol.Entry, *protocol.DeviceKeys) {
	t.Helper()
	dev := mustDevice(t)
	e := nextEntry(t, acct, acct.Genesis, protocol.OpAdd, protocol.SignerAK, dev)
	e.Sig = bytes.Repeat([]byte{0x5a}, ed25519.SignatureSize)
	return e, dev
}

// A MEMBER CANNOT BRICK THE CHAIN WITH A JUNK SIGNATURE. Structure alone let
// one through: the relay stored it, the named key got a full session, and
// every client's verification failed on it for ever.
func TestAnAppendWithABadSignatureIsRefused(t *testing.T) {
	srv, db := instance(t)
	a := client.New(srv.URL, true)
	acct, err := a.Register("quiet-otter-41", invite(t, db)) // sends the epoch-1 key
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Login(); err != nil {
		t.Fatal(err)
	}
	bad, dev := junkSigned(t, acct)
	if err := a.AppendRoster(bad); err == nil || !strings.Contains(err.Error(), "400") {
		t.Fatalf("a junk-signed add was stored: %v", err)
	}
	x := client.New(srv.URL, true)
	x.Account, x.Device = acct.Root.AccountID, dev
	if err := x.Login(); err != nil {
		t.Fatal(err)
	}
	if _, err := x.PutObject("servers", 1, 1, []byte("x"), ""); err == nil {
		t.Fatal("the key a junk entry named got a member's session")
	}
	// The real thing still goes through.
	addedDevice(t, srv.URL, a, acct)
}

// AN ACCOUNT REGISTERED WITHOUT THE KEY supplies it later, and only the right
// one is taken: it must verify the stored chain from genesis.
func TestTheEpoch1KeyCanBeSuppliedLater(t *testing.T) {
	srv, db := instance(t)
	acct, err := protocol.NewAccount("quiet-otter-41")
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := acct.Genesis.Wire()
	body, _ := json.Marshal(map[string]string{
		"account":       acct.Root.AccountID.String(),
		"root_sign_pub": hex.EncodeToString(acct.Root.Sign.Public().(ed25519.PublicKey)),
		"invite":        invite(t, db),
		"genesis":       base64.StdEncoding.EncodeToString(wire),
		"escrow":        base64.StdEncoding.EncodeToString(acct.Escrow),
	})
	resp, err := srv.Client().Post(srv.URL+"/v1/account", "application/json", bytes.NewReader(body))
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("registering without the key: %v %v", err, resp.Status)
	}
	a := client.New(srv.URL, true)
	a.Account, a.Device = acct.Root.AccountID, acct.Device
	if err := a.Login(); err != nil {
		t.Fatal(err)
	}

	wrong := hex.EncodeToString(mustDevice(t).Sign.Public().(ed25519.PublicKey))
	if code, _ := callStatus(t, a, http.MethodPost, "/v1/roster/epoch1", map[string]string{"epoch1_sign_pub": wrong}); code != http.StatusBadRequest {
		t.Errorf("a key that does not verify the genesis entry answered %d, want 400", code)
	}
	right := hex.EncodeToString(acct.Epoch.Sign.Public().(ed25519.PublicKey))
	if code, msg := callStatus(t, a, http.MethodPost, "/v1/roster/epoch1", map[string]string{"epoch1_sign_pub": right}); code != http.StatusNoContent {
		t.Fatalf("the right key answered %d %s", code, msg)
	}
	bad, _ := junkSigned(t, acct)
	if err := a.AppendRoster(bad); err == nil {
		t.Fatal("after the key was supplied, a junk-signed add was still stored")
	}
}

// The escrow is what recovery opens; nothing deletes it.
func TestTheEscrowCannotBeDeleted(t *testing.T) {
	srv, db := instance(t)
	a := client.New(srv.URL, true)
	if _, err := a.Register("quiet-otter-41", invite(t, db)); err != nil {
		t.Fatal(err)
	}
	if err := a.Login(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/v1/obj/escrow", "/v1/obj/escrow?epoch=1"} {
		if code, _ := callStatus(t, a, http.MethodDelete, path, nil); code != http.StatusForbidden {
			t.Errorf("DELETE %s = %d, want 403", path, code)
		}
	}
	if _, err := a.GetObject("escrow", 1); err != nil {
		t.Errorf("the escrow is gone: %v", err)
	}
}

// The unauthenticated routes read a bounded body, say 413 past it, and the
// challenge stores nothing it has not checked.
func TestUnauthenticatedBodiesAreBoundedAndChecked(t *testing.T) {
	srv, _ := instance(t)
	post := func(path, body string) int {
		resp, err := srv.Client().Post(srv.URL+path, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	huge := `{"account":"` + strings.Repeat("a", 70<<10) + `"}`
	for _, path := range []string{"/v1/auth/challenge", "/v1/auth/login", "/v1/account", "/v1/pair/" + strings.Repeat("ab", 16) + "?as=initiator"} {
		if got := post(path, huge); got != http.StatusRequestEntityTooLarge {
			t.Errorf("an oversized body to %s = %d, want 413", path, got)
		}
	}
	for _, body := range []string{`{}`, `{"account":"zz","device":"zz"}`, `{"account":"` + strings.Repeat("ab", 16) + `","device":"00"}`} {
		if got := post("/v1/auth/challenge", body); got != http.StatusBadRequest {
			t.Errorf("challenge %s = %d, want 400", body, got)
		}
	}
}

// A long poll parked before a revoke is not answered after it.
func TestALongPollParkedBeforeARevokeIsNotAnswered(t *testing.T) {
	srv, db, s := instanceWithAPI(t)
	s.PollWait = 3 * time.Second
	a := client.New(srv.URL, true)
	acct, err := a.Register("quiet-otter-41", invite(t, db))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Login(); err != nil {
		t.Fatal(err)
	}
	b, add := addedDevice(t, srv.URL, a, acct)

	got := make(chan int, 1)
	go func() {
		code, _ := callStatus(t, b, http.MethodGet, "/v1/changes", nil)
		got <- code
	}()
	time.Sleep(200 * time.Millisecond)
	if err := a.AppendRoster(nextEntry(t, acct, add, protocol.OpRevoke, protocol.SignerAK, b.Device)); err != nil {
		t.Fatal(err)
	}
	if _, err := a.PutObject("servers", 1, 1, []byte("sealed"), ""); err != nil {
		t.Fatal(err)
	}
	if code := <-got; code != http.StatusUnauthorized {
		t.Errorf("the revoked device's parked poll answered %d, want 401", code)
	}
}

// A MEMBER CANNOT WRITE THE ESCROW. Recovery reads one past the roster's end
// as proof of a rollback, so a paired device that could PUT junk at epoch n+1
// made recovery refuse for good; one that could overwrite epoch 1's decided
// what the phrase recovers. Only the root key's signature admits a write.
func TestOnlyTheRootKeyWritesTheEscrow(t *testing.T) {
	srv, db := instance(t)
	a := client.New(srv.URL, true)
	acct, err := a.Register("quiet-otter-41", invite(t, db))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Login(); err != nil {
		t.Fatal(err)
	}
	for _, epoch := range []uint64{1, 2} {
		if _, err := a.PutObject("escrow", epoch, 1, []byte("junk"), ""); err == nil || !strings.Contains(err.Error(), "403") {
			t.Errorf("a member wrote the epoch-%d escrow unsigned: %v", epoch, err)
		}
		// Signed, but by the device rather than the root key.
		if _, err := a.PutEscrow(epoch, 1, []byte("junk"), a.Device.Sign); err == nil || !strings.Contains(err.Error(), "403") {
			t.Errorf("a device key's signature wrote the epoch-%d escrow: %v", epoch, err)
		}
	}
	if _, err := a.GetObject("escrow", 2); err == nil {
		t.Fatal("something was stored at epoch 2")
	}
	got, err := a.GetObject("escrow", 1)
	if err != nil || !bytes.Equal(got.Body, acct.Escrow) {
		t.Fatalf("the epoch-1 escrow changed: %v", err)
	}

	// The root key's signature over exactly this write goes through.
	if _, err := a.PutEscrow(2, 1, []byte("sealed at epoch 2"), acct.Root.Sign); err != nil {
		t.Fatalf("a root-signed escrow write was refused: %v", err)
	}
	if got, err := a.GetObject("escrow", 2); err != nil || string(got.Body) != "sealed at epoch 2" {
		t.Fatalf("the root-signed escrow is not what was stored: %v", err)
	}
	// What the signature binds -- account, epoch, counter, the bytes -- is
	// pinned field by field in protocol.TestEscrowWriteBindsEveryField.
}

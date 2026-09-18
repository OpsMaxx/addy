package api_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/opsmaxx/addy/internal/client"
)

// What a device is told about relaying, in the three configurations an
// operator can be in.

func turnAnswer(t *testing.T, c *client.Client) map[string]any {
	t.Helper()
	raw, err := c.CapturedRequestForTest(http.MethodGet, "/v1/turn")
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	resp, err := c.HTTP.Do(raw)
	if err != nil {
		t.Fatalf("GET /v1/turn: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/turn answered %s", resp.Status)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

// "There is no relay" is a legitimate configuration, and a device has to be
// told so clearly rather than by a 404 it has to interpret -- otherwise it
// reports "could not connect" for a pair of networks that simply needs a relay
// this box does not run.
func TestADeviceIsToldPlainlyWhenThereIsNoRelay(t *testing.T) {
	srv, db := instance(t)
	c := client.New(srv.URL, true)
	if _, err := c.Register("one", invite(t, db)); err != nil {
		t.Fatal(err)
	}
	if err := c.Login(); err != nil {
		t.Fatal(err)
	}

	got := turnAnswer(t, c)
	if got["mode"] != "none" {
		t.Fatalf("mode is %v on an instance with no relay", got["mode"])
	}
	if _, present := got["credential"]; present {
		t.Fatalf("a credential was issued by an instance with no relay: %v", got)
	}
}

func TestAnExternalRelayIsPassedThroughWithNoCredential(t *testing.T) {
	srv, db, api := instanceWithAPI(t)
	api.TurnExternal = "turn:relay.example:3478?transport=udp"

	c := client.New(srv.URL, true)
	if _, err := c.Register("one", invite(t, db)); err != nil {
		t.Fatal(err)
	}
	if err := c.Login(); err != nil {
		t.Fatal(err)
	}

	got := turnAnswer(t, c)
	if got["mode"] != "external" {
		t.Fatalf("mode is %v", got["mode"])
	}
	if got["url"] != "turn:relay.example:3478?transport=udp" {
		t.Fatalf("url is %v", got["url"])
	}
	// The operator's own relay has its own arrangements; addy inventing a
	// credential for it would be addy guessing at somebody else's config.
	if _, present := got["credential"]; present {
		t.Fatal("addy minted a credential for a relay it does not run")
	}
}

type fixedMinter struct{ calls *int }

func (m fixedMinter) Mint(device string) any {
	*m.calls++
	return map[string]string{"username": "1700000000:" + device, "password": "derived"}
}

// A CREDENTIAL PER DEVICE, per request. A long-lived shared secret handed to
// every device is an open relay one leaked config file away, and relaying is
// the operator's bandwidth.
func TestAnEmbeddedRelayMintsPerDevice(t *testing.T) {
	srv, db, api := instanceWithAPI(t)
	calls := 0
	api.Turn = fixedMinter{calls: &calls}

	c := client.New(srv.URL, true)
	if _, err := c.Register("one", invite(t, db)); err != nil {
		t.Fatal(err)
	}
	if err := c.Login(); err != nil {
		t.Fatal(err)
	}

	got := turnAnswer(t, c)
	if got["mode"] != "embedded" {
		t.Fatalf("mode is %v", got["mode"])
	}
	cred, ok := got["credential"].(map[string]any)
	if !ok {
		t.Fatalf("no credential: %v", got)
	}
	// Named for the device that asked, so an abuse report names a device
	// rather than the whole instance.
	if username, _ := cred["username"].(string); len(username) < 20 {
		t.Fatalf("username is %q", username)
	}

	// Fresh every time, not cached.
	turnAnswer(t, c)
	if calls != 2 {
		t.Fatalf("the relay minted %d credentials for two requests", calls)
	}
}

// External wins over embedded. An operator who configured both meant the
// external one, because configuring it is the deliberate act.
func TestAnExternalRelayWinsOverAnEmbeddedOne(t *testing.T) {
	srv, db, api := instanceWithAPI(t)
	calls := 0
	api.Turn = fixedMinter{calls: &calls}
	api.TurnExternal = "turn:relay.example:3478"

	c := client.New(srv.URL, true)
	if _, err := c.Register("one", invite(t, db)); err != nil {
		t.Fatal(err)
	}
	if err := c.Login(); err != nil {
		t.Fatal(err)
	}

	if got := turnAnswer(t, c); got["mode"] != "external" {
		t.Fatalf("mode is %v", got["mode"])
	}
	if calls != 0 {
		t.Fatal("the embedded relay minted a credential that nothing would use")
	}
}

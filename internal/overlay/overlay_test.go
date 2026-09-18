package overlay_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/opsmaxx/addy/internal/overlay"
)

// A fake headscale, so the shape of the request can be asserted without one.
func fakeHeadscale(t *testing.T, seen *map[string]any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/preauthkey" || r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") != "Bearer test-api-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		*seen = body
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"preAuthKey":{"key":"abc123","expiration":"2026-09-18T12:00:00Z"}}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func minter(t *testing.T, url string) *overlay.Minter {
	t.Helper()
	m, err := overlay.New(overlay.Config{BaseURL: url, APIKey: "test-api-key", User: "addy"})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// SINGLE USE, SHORT LIVED, AND NOT EPHEMERAL.
//
// A reusable key is a key that leaks once and admits anyone forever. The
// roster is what makes minting a fresh one per device cheap enough that
// reusable has no excuse, so asking for one would be giving up the only
// advantage this design has.
func TestAMintedKeyIsSingleUseAndShortLived(t *testing.T) {
	var seen map[string]any
	srv := fakeHeadscale(t, &seen)

	key, err := minter(t, srv.URL).Mint(t.Context(), []byte{0xde, 0xad, 0xbe, 0xef}, "https://relay.example")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if key.Key != "abc123" {
		t.Fatalf("the key came back as %q", key.Key)
	}
	// A key without the control URL is half an answer, and the two have to
	// agree.
	if key.ControlURL != "https://relay.example" {
		t.Fatalf("control URL is %q", key.ControlURL)
	}

	if seen["reusable"] != false {
		t.Error("the key was asked for as reusable")
	}
	// Not ephemeral either: an ephemeral node vanishes from headscale when it
	// disconnects, which would make the node list useless for the one job it
	// has here -- matching a machine to a roster entry when somebody is
	// revoking it.
	if seen["ephemeral"] != false {
		t.Error("the key was asked for as ephemeral")
	}

	expiry, ok := seen["expiration"].(string)
	if !ok {
		t.Fatal("no expiration was requested")
	}
	at, err := time.Parse(time.RFC3339, expiry)
	if err != nil {
		t.Fatalf("expiration %q does not parse", expiry)
	}
	// Minutes, not days. The device is waiting on the other end of a button
	// press, so anything longer is a window with no purpose.
	if until := time.Until(at); until > time.Hour {
		t.Fatalf("the key is good for %s; it is handed to a device that is already waiting", until)
	}
}

// The tag is how an operator matches a headscale node to a roster entry, which
// matters at the only moment it ever does: a device is revoked in addy and
// somebody has to find the node and remove it.
func TestTheKeyIsTaggedWithTheDevice(t *testing.T) {
	var seen map[string]any
	srv := fakeHeadscale(t, &seen)

	if _, err := minter(t, srv.URL).Mint(t.Context(), []byte{0xde, 0xad, 0xbe, 0xef}, "https://relay.example"); err != nil {
		t.Fatal(err)
	}
	tags, ok := seen["aclTags"].([]any)
	if !ok || len(tags) != 1 {
		t.Fatalf("aclTags is %v", seen["aclTags"])
	}
	tag := tags[0].(string)
	// headscale requires the `tag:` prefix and rejects anything else, which is
	// the sort of thing discovered at deployment rather than in review.
	if !strings.HasPrefix(tag, "tag:") {
		t.Fatalf("the tag %q has no `tag:` prefix; headscale rejects those", tag)
	}
	if !strings.Contains(tag, "deadbeef") {
		t.Fatalf("the tag %q does not name the device", tag)
	}
}

// The message has to be about the OPERATOR's configuration: a 401 here means
// addy's API key is wrong, which is nothing the person pressing the button can
// fix and everything the person who deployed headscale can.
func TestAWrongApiKeySaysWhoseProblemItIs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	m, err := overlay.New(overlay.Config{BaseURL: srv.URL, APIKey: "wrong", User: "addy"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.Mint(t.Context(), []byte{1}, "https://relay.example")
	if err == nil {
		t.Fatal("a 401 was treated as success")
	}
	if !strings.Contains(err.Error(), "API key") {
		t.Fatalf("the error does not point at the configuration: %v", err)
	}
}

func TestItRefusesToBeConfiguredWithHalfACredential(t *testing.T) {
	for _, cfg := range []overlay.Config{
		{BaseURL: "http://127.0.0.1:8080"},
		{APIKey: "k"},
		{},
	} {
		if _, err := overlay.New(cfg); err == nil {
			t.Errorf("New accepted %+v", cfg)
		}
	}
}

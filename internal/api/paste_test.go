package api_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/opsmaxx/addy/internal/client"
)

// The paste routes, and the asymmetry that defines them: creating one needs an
// account on this box, reading one cannot -- the recipient of a link has no
// account here and cannot be made to get one.

func pasteInstance(t *testing.T) (string, *client.Client) {
	t.Helper()
	srv, db := instance(t)
	c := client.New(srv.URL, true)
	if _, err := c.Register("one", invite(t, db)); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := c.Login(); err != nil {
		t.Fatalf("login: %v", err)
	}
	return srv.URL, c
}

// create posts a paste as the authenticated client and returns its id.
func create(t *testing.T, c *client.Client, body string, maxViews int) string {
	t.Helper()
	id, err := c.CreatePaste([]byte(body), 3600, maxViews)
	if err != nil {
		t.Fatalf("CreatePaste: %v", err)
	}
	return id
}

// get and burn go over plain HTTP with no credentials at all, which is exactly
// how a recipient reaches them.
func anonymous(t *testing.T, c *client.Client, method, path string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, c.BaseURL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

func TestAnAnonymousReaderCanBurnAPaste(t *testing.T) {
	_, c := pasteInstance(t)
	id := create(t, c, "sealed bytes", 1)

	status, body := anonymous(t, c, http.MethodPost, "/v1/paste/"+id+"/burn")
	if status != http.StatusOK {
		t.Fatalf("burn answered %d: %s", status, body)
	}
	var out struct {
		Sealed    string `json:"sealed"`
		Remaining int    `json:"remaining"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	got, err := base64.StdEncoding.DecodeString(out.Sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("sealed bytes")) {
		t.Fatalf("burn returned %q", got)
	}
	if out.Remaining != 0 {
		t.Fatalf("remaining is %d after burning a one-view paste", out.Remaining)
	}

	// And it is gone.
	if status, _ := anonymous(t, c, http.MethodPost, "/v1/paste/"+id+"/burn"); status != http.StatusGone {
		t.Fatalf("a second burn answered %d, want 410", status)
	}
}

// THE FAILURE MODE EVERY ONE-TIME PASTE SERVICE DIES OF.
//
// The link is posted in a chat app, the app fetches it to build a preview, the
// paste burns, and the human gets an empty page. Headers and robots.txt help
// with the crawlers that read them; this is the part that works against the
// ones that do not.
func TestAPrefetchCannotBurnAPaste(t *testing.T) {
	_, c := pasteInstance(t)
	id := create(t, c, "sealed bytes", 1)

	// A link previewer, a mail scanner and a browser's speculative fetch.
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodGet} {
		if status, body := anonymous(t, c, method, "/v1/paste/"+id); status != http.StatusOK {
			t.Fatalf("%s answered %d: %s", method, status, body)
		}
	}

	// The human still gets it.
	if status, _ := anonymous(t, c, http.MethodPost, "/v1/paste/"+id+"/burn"); status != http.StatusOK {
		t.Fatalf("the paste burned before the recipient opened it (%d)", status)
	}
}

// The anonymous view is a separate serializer, and this is what it must not
// carry.
func TestTheAnonymousViewLeaksNothing(t *testing.T) {
	_, c := pasteInstance(t)
	id := create(t, c, "sealed bytes", 1)

	status, body := anonymous(t, c, http.MethodGet, "/v1/paste/"+id)
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}
	var fields map[string]any
	if err := json.Unmarshal(body, &fields); err != nil {
		t.Fatal(err)
	}
	// A reader needs to know whether they can read it, not who sent it, how
	// big it is, or how many other people have looked.
	for _, forbidden := range []string{"owner", "sealed", "views", "createdAt", "expiresAt"} {
		if _, present := fields[forbidden]; present {
			t.Errorf("the anonymous view carries %q: %s", forbidden, body)
		}
	}
	if fields["state"] != "ready" {
		t.Errorf("state is %v", fields["state"])
	}
	// `burns` is there so the page can warn BEFORE the reader clicks rather
	// than after.
	if fields["burns"] != true {
		t.Errorf("a one-view paste does not announce that it burns: %s", body)
	}
}

func TestABurnedPasteSaysGoneRatherThanMissing(t *testing.T) {
	_, c := pasteInstance(t)
	id := create(t, c, "sealed", 1)

	if status, _ := anonymous(t, c, http.MethodPost, "/v1/paste/"+id+"/burn"); status != http.StatusOK {
		t.Fatal("the first burn failed")
	}

	// 410 with a body, not 404: the sender can tell "they read it" from "I
	// sent the wrong link", and the page can say which.
	status, body := anonymous(t, c, http.MethodGet, "/v1/paste/"+id)
	if status != http.StatusGone {
		t.Fatalf("a burned paste answered %d: %s", status, body)
	}
	if !strings.Contains(string(body), `"state":"gone"`) {
		t.Fatalf("the 410 does not say it was a paste: %s", body)
	}

	// An id that never existed is a 404, and the two must not converge.
	if status, _ := anonymous(t, c, http.MethodGet, "/v1/paste/aaaaaaaaaaaaaaaaaaaaaa"); status != http.StatusNotFound {
		t.Fatalf("an unknown id answered %d, want 404", status)
	}
}

func TestCreatingAPasteNeedsAnAccount(t *testing.T) {
	_, c := pasteInstance(t)

	// An open create endpoint on a self-hosted box is a free anonymous file
	// drop for whoever finds it, and the operator ends up hosting other
	// people's content under their own domain.
	req, err := http.NewRequest(http.MethodPost, c.BaseURL+"/v1/paste",
		strings.NewReader(`{"sealed":"aGVsbG8=","ttlSeconds":60,"maxViews":1}`))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("an unauthenticated create answered %s", resp.Status)
	}
}

func TestPasteResponsesAreNotCached(t *testing.T) {
	_, c := pasteInstance(t)
	id := create(t, c, "sealed", 1)

	req, _ := http.NewRequest(http.MethodGet, c.BaseURL+"/v1/paste/"+id, nil)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// A shared proxy or a back button holding the response is a copy of the
	// ciphertext that outlives the burn -- and the key is in the URL the same
	// cache is keyed on.
	if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Fatalf("Cache-Control is %q", cc)
	}
	if rt := resp.Header.Get("X-Robots-Tag"); !strings.Contains(rt, "noindex") {
		t.Fatalf("X-Robots-Tag is %q", rt)
	}
}

func TestAPanickedInstanceServesNoPastes(t *testing.T) {
	srv, db := instance(t)
	c := client.New(srv.URL, true)
	if _, err := c.Register("one", invite(t, db)); err != nil {
		t.Fatal(err)
	}
	if err := c.Login(); err != nil {
		t.Fatal(err)
	}
	id := create(t, c, "sealed", 1)

	if _, err := db.Panic(t.Context()); err != nil {
		t.Fatal(err)
	}

	// The paste routes are anonymous, so they do not go through `authed` and
	// do not get its reonboard check for free. Without their own, an operator
	// who ran `addy panic` would have stopped their devices syncing and left
	// the box handing out user content from a machine they just disowned.
	if status, _ := anonymous(t, c, http.MethodGet, "/v1/paste/"+id); status != http.StatusServiceUnavailable {
		t.Fatalf("a panicked instance answered %d for a paste read", status)
	}
	if status, _ := anonymous(t, c, http.MethodPost, "/v1/paste/"+id+"/burn"); status != http.StatusServiceUnavailable {
		t.Fatalf("a panicked instance answered %d for a burn", status)
	}
}

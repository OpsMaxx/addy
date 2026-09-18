package api_test

import (
	"net/http"
	"testing"

	"github.com/opsmaxx/addy/internal/client"
)

// A panicked or reset instance stops serving devices, without a restart.
//
// The flag is read from the database on every authenticated request rather
// than cached at startup, and that is the whole point: `addy panic` is a
// separate process writing to the same file, and a cached flag would leave a
// running server serving until somebody remembered to restart it -- which is
// precisely the moment nobody is thinking about restarts.
func TestAPanickedInstanceRefusesEveryDevice(t *testing.T) {
	srv, db := instance(t)

	c := client.New(srv.URL, true)
	if _, err := c.Register("one", invite(t, db)); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := c.Login(); err != nil {
		t.Fatalf("login: %v", err)
	}
	if _, err := c.PutObject("servers", 1, 1, []byte("before"), ""); err != nil {
		t.Fatalf("a healthy instance refused a write: %v", err)
	}

	// The same process that was serving a moment ago, with a live session.
	if _, err := db.Panic(t.Context()); err != nil {
		t.Fatalf("Panic: %v", err)
	}

	if _, err := c.GetObject("servers", 1); err == nil {
		t.Fatal("a panicked instance served a read on an existing session")
	}
	if _, err := c.PutObject("servers", 1, 2, []byte("after"), ""); err == nil {
		t.Fatal("a panicked instance accepted a write")
	}
}

// 503 rather than 401, and the distinction is not cosmetic: a client that read
// this as an authentication failure would re-login in a loop against a box
// somebody has deliberately taken out of service.
func TestAPanickedInstanceAnswers503(t *testing.T) {
	srv, db := instance(t)

	c := client.New(srv.URL, true)
	if _, err := c.Register("one", invite(t, db)); err != nil {
		t.Fatal(err)
	}
	if err := c.Login(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Panic(t.Context()); err != nil {
		t.Fatal(err)
	}

	raw, err := c.CapturedRequestForTest(http.MethodGet, "/v1/roster")
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	resp, err := c.HTTP.Do(raw)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("a panicked instance answered %s", resp.Status)
	}
	// Carries WHEN, so a client can tell the user something more useful than
	// "unavailable" and an operator reading a support log can match it against
	// the moment they ran the command.
	if resp.Header.Get("X-Addy-Reonboard") == "" {
		t.Fatal("the 503 does not say when the instance was taken out of service")
	}
}

// Clearing it puts the instance back, and only from the console -- there is no
// route that reaches ClearReonboard.
func TestClearingReonboardRestoresService(t *testing.T) {
	srv, db := instance(t)

	c := client.New(srv.URL, true)
	if _, err := c.Register("one", invite(t, db)); err != nil {
		t.Fatal(err)
	}
	if err := c.Login(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Panic(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := db.ClearReonboard(t.Context()); err != nil {
		t.Fatal(err)
	}

	if _, err := c.PutObject("servers", 1, 1, []byte("again"), ""); err != nil {
		t.Fatalf("a cleared instance still refuses: %v", err)
	}
}

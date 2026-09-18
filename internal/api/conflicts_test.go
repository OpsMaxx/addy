package api_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/opsmaxx/addy/internal/client"
)

// The loser of a race keeps its bytes, and a person gets to choose.
//
// A bare last-writer-wins silently destroys one device's work and tells
// nobody. For a `servers` list that means a machine somebody added on the
// laptop is simply gone from the desktop, with no error and no symptom -- and
// they find out when they need that machine.

func conflictClient(t *testing.T) *client.Client {
	t.Helper()
	srv, db := instance(t)
	c := client.New(srv.URL, true)
	if _, err := c.Register("one", invite(t, db)); err != nil {
		t.Fatal(err)
	}
	if err := c.Login(); err != nil {
		t.Fatal(err)
	}
	return c
}

func post(t *testing.T, c *client.Client, path string, body any) *http.Response {
	t.Helper()
	resp, err := c.RawRequest(http.MethodPost, path, body)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	return resp
}

func TestALosingCopyIsKeptAndOffered(t *testing.T) {
	c := conflictClient(t)

	// The winner.
	if _, err := c.PutObject("servers", 1, 1, []byte("the desktop's list"), ""); err != nil {
		t.Fatal(err)
	}

	// The loser keeps its own bytes, which is the only moment they exist
	// anywhere but in its memory.
	resp := post(t, c, "/v1/obj/servers/conflict", map[string]any{
		"epoch":   1,
		"counter": 1,
		"body":    base64.StdEncoding.EncodeToString([]byte("the laptop's list")),
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("keeping a conflict answered %s", resp.Status)
	}

	listed, err := c.RawRequest(http.MethodGet, "/v1/conflicts", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listed.Body.Close()
	var out struct {
		Conflicts []struct {
			ID     int64  `json:"id"`
			Name   string `json:"name"`
			Device string `json:"device"`
			Body   string `json:"body"`
		} `json:"conflicts"`
	}
	if err := json.NewDecoder(listed.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Conflicts) != 1 {
		t.Fatalf("%d conflicts waiting", len(out.Conflicts))
	}
	got := out.Conflicts[0]
	if got.Name != "servers" {
		t.Fatalf("the conflict names %q", got.Name)
	}
	// Who wrote it. "The copy from your laptop" is a question somebody can
	// answer; "copy B" is not.
	if got.Device == "" {
		t.Error("the conflict does not say which device wrote it")
	}
	body, _ := base64.StdEncoding.DecodeString(got.Body)
	if string(body) != "the laptop's list" {
		t.Fatalf("the losing bytes came back as %q", body)
	}

	// The winner is untouched. The whole point is that neither copy is lost.
	winner, err := c.GetObject("servers", 1)
	if err != nil {
		t.Fatal(err)
	}
	if string(winner.Body) != "the desktop's list" {
		t.Fatalf("the winning copy is now %q", winner.Body)
	}
}

func TestResolvingAConflictStopsItBeingOffered(t *testing.T) {
	c := conflictClient(t)
	if _, err := c.PutObject("servers", 1, 1, []byte("winner"), ""); err != nil {
		t.Fatal(err)
	}
	resp := post(t, c, "/v1/obj/servers/conflict", map[string]any{
		"epoch": 1, "counter": 1,
		"body": base64.StdEncoding.EncodeToString([]byte("loser")),
	})
	resp.Body.Close()

	listed, _ := c.RawRequest(http.MethodGet, "/v1/conflicts", nil)
	var out struct {
		Conflicts []struct {
			ID int64 `json:"id"`
		} `json:"conflicts"`
	}
	json.NewDecoder(listed.Body).Decode(&out)
	listed.Body.Close()

	done := post(t, c, "/v1/conflicts/"+itoa(out.Conflicts[0].ID)+"/resolve", nil)
	done.Body.Close()
	if done.StatusCode != http.StatusNoContent {
		t.Fatalf("resolve answered %s", done.Status)
	}

	// Leaving it would mean the chooser offering the same decision forever.
	again, _ := c.RawRequest(http.MethodGet, "/v1/conflicts", nil)
	var after struct {
		Conflicts []json.RawMessage `json:"conflicts"`
	}
	json.NewDecoder(again.Body).Decode(&after)
	again.Body.Close()
	if len(after.Conflicts) != 0 {
		t.Fatalf("%d conflicts survived resolution", len(after.Conflicts))
	}
}

func TestOneAccountCannotSeeAnothersConflicts(t *testing.T) {
	a, _, b, _ := twoAccounts(t)

	if _, err := a.PutObject("servers", 1, 1, []byte("A's"), ""); err != nil {
		t.Fatal(err)
	}
	resp, err := a.RawRequest(http.MethodPost, "/v1/obj/servers/conflict", map[string]any{
		"epoch": 1, "counter": 1,
		"body": base64.StdEncoding.EncodeToString([]byte("A's losing copy")),
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// A conflict copy is a document's contents by another name, so the
	// isolation that covers objects has to cover these too.
	listed, err := b.RawRequest(http.MethodGet, "/v1/conflicts", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listed.Body.Close()
	var out struct {
		Conflicts []json.RawMessage `json:"conflicts"`
	}
	json.NewDecoder(listed.Body).Decode(&out)
	if len(out.Conflicts) != 0 {
		t.Fatalf("B sees %d of A's conflicts", len(out.Conflicts))
	}
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

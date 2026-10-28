package api_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/opsmaxx/addy/internal/client"
	"github.com/opsmaxx/addy/internal/protocol"
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

// AN EPOCH ADVANCING TAKES THE OLDER EPOCHS' CONFLICT COPIES WITH IT.
//
// A re-key is what removing a device does, and a copy sealed before it may be
// the removed device's own. Kept, it was one click on "Replace it with the
// other copy" from being re-sealed under the new key and pushed everywhere. A
// copy kept AFTER the transition -- including by an OpsMaxx 0.59.0 client,
// which posts exactly what it always did -- is still accepted and offered.
func TestATransitionDropsConflictCopiesFromOlderEpochs(t *testing.T) {
	srv, db := instance(t)
	c := client.New(srv.URL, true)
	acct, err := c.Register("one", invite(t, db))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Login(); err != nil {
		t.Fatal(err)
	}
	keep := func(epoch int, body string) {
		t.Helper()
		resp := post(t, c, "/v1/obj/servers/conflict", map[string]any{
			"epoch": epoch, "counter": 2, "body": base64.StdEncoding.EncodeToString([]byte(body)),
		})
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("keeping a conflict at epoch %d answered %s", epoch, resp.Status)
		}
	}
	listed := func() []uint64 {
		t.Helper()
		resp, err := c.RawRequest(http.MethodGet, "/v1/conflicts", nil)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out struct {
			Conflicts []struct {
				Epoch uint64 `json:"epoch"`
			} `json:"conflicts"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		var epochs []uint64
		for _, x := range out.Conflicts {
			epochs = append(epochs, x.Epoch)
		}
		return epochs
	}

	keep(1, "sealed before the re-key")

	wire, err := acct.Genesis.Wire()
	if err != nil {
		t.Fatal(err)
	}
	rootPub := acct.Root.Sign.Public().(ed25519.PublicKey)
	verified, err := protocol.VerifyChain(wire, acct.Root.AccountID, rootPub,
		acct.Epoch.Sign.Public().(ed25519.PublicKey), nil)
	if err != nil {
		t.Fatal(err)
	}
	// A revocation re-key: the removed device may have posted these.
	rot, err := protocol.PrepareRotation(protocol.Revocation, acct.Root.AccountID, verified,
		acct.Genesis, acct.Root.Sign, rootPub)
	if err != nil {
		t.Fatal(err)
	}
	if got := listed(); len(got) != 1 {
		t.Fatalf("before the transition %v conflicts were listed, want one", got)
	}
	if err := c.AppendRoster(rot.Entry); err != nil {
		t.Fatalf("appending the transition: %v", err)
	}
	if got := listed(); len(got) != 0 {
		t.Fatalf("epoch-1 conflict copies survived a revocation re-key: %v", got)
	}

	keep(2, "sealed after it")
	if got := listed(); len(got) != 1 || got[0] != 2 {
		t.Fatalf("after the transition the listing is %v, want [2]", got)
	}
}

// A ROUTINE ROTATION REMOVES NOBODY, so its unresolved conflict copies are
// kept: they may be the only place that work exists.
func TestAHygieneRotationKeepsConflictCopies(t *testing.T) {
	srv, db := instance(t)
	c := client.New(srv.URL, true)
	acct, err := c.Register("one", invite(t, db))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Login(); err != nil {
		t.Fatal(err)
	}
	resp := post(t, c, "/v1/obj/servers/conflict", map[string]any{
		"epoch": 1, "counter": 2, "body": base64.StdEncoding.EncodeToString([]byte("unresolved")),
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("keeping a conflict answered %s", resp.Status)
	}
	wire, err := acct.Genesis.Wire()
	if err != nil {
		t.Fatal(err)
	}
	rootPub := acct.Root.Sign.Public().(ed25519.PublicKey)
	verified, err := protocol.VerifyChain(wire, acct.Root.AccountID, rootPub,
		acct.Epoch.Sign.Public().(ed25519.PublicKey), nil)
	if err != nil {
		t.Fatal(err)
	}
	rot, err := protocol.PrepareRotation(protocol.Hygiene, acct.Root.AccountID, verified,
		acct.Genesis, acct.Epoch.Sign, rootPub)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.AppendRoster(rot.Entry); err != nil {
		t.Fatalf("appending the transition: %v", err)
	}
	n, err := db.Conflicts(context.Background(), acct.Root.AccountID.String())
	if err != nil {
		t.Fatal(err)
	}
	if len(n) != 1 {
		t.Fatalf("a hygiene rotation dropped %d unresolved conflict copies", 1-len(n))
	}
}

package frontdoor

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

func mustSet(t *testing.T, tbl *Table, r Route) {
	t.Helper()
	if err := tbl.Set(r); err != nil {
		t.Fatalf("Set(%+v): %v", r, err)
	}
}

// The open-issuance-relay case. This is the single most important assertion in
// the package: a DecisionFunc that says yes to an unconfigured name lets any
// stranger with a DNS record burn the instance's ACME rate limit.
func TestDecideRefusesAnUnconfiguredHost(t *testing.T) {
	tbl := NewTable()
	mustSet(t, tbl, Route{Host: "addy.example", Mode: Terminate})

	err := tbl.Decide(context.Background(), "stranger.example")
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("Decide(unconfigured) = %v, want ErrNotConfigured", err)
	}
}

// A name whose handshake we never terminate must never be issued for. If
// on-demand fires for one, something is misrouted, and a certificate would hide
// the misrouting behind a working handshake.
func TestDecideRefusesAPassthroughHost(t *testing.T) {
	tbl := NewTable()
	mustSet(t, tbl, Route{Host: "*.tun.example", Mode: Passthrough, Backend: "127.0.0.1:8443"})

	err := tbl.Decide(context.Background(), "a.tun.example")
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("Decide(passthrough) = %v, want a refusal", err)
	}
}

// The happy path, so the two refusal tests above cannot pass by refusing
// everything -- which is the way a security check most often breaks.
func TestDecideAllowsAConfiguredHost(t *testing.T) {
	tbl := NewTable()
	mustSet(t, tbl, Route{Host: "addy.example", Mode: Terminate})
	mustSet(t, tbl, Route{Host: "vault.example", Mode: Proxy, Backend: "127.0.0.1:8222"})

	for _, host := range []string{"addy.example", "vault.example", "ADDY.example.", "vault.example:443"} {
		if err := tbl.Decide(context.Background(), host); err != nil {
			t.Errorf("Decide(%q) = %v, want nil", host, err)
		}
	}
}

// A wildcard matches exactly one label, the way a TLS wildcard certificate
// does. The looser suffix reading is what people write by accident, and it
// silently widens the allowlist to every depth of subdomain.
func TestWildcardMatchesOneLabelOnly(t *testing.T) {
	tbl := NewTable()
	mustSet(t, tbl, Route{Host: "*.tun.example", Mode: Passthrough, Backend: "127.0.0.1:8443"})

	cases := map[string]bool{
		"a.tun.example":   true,
		"b.tun.example":   true,
		"tun.example":     false, // the bare name is not covered
		"a.b.tun.example": false, // two labels deep is not covered
		"a.tun.other":     false,
		".tun.example":    false, // an empty label is not a label
	}
	for host, want := range cases {
		_, got := tbl.Lookup(host)
		if got != want {
			t.Errorf("Lookup(%q) matched = %v, want %v", host, got, want)
		}
	}
}

func TestExactBeatsWildcardAndLongestWildcardWins(t *testing.T) {
	tbl := NewTable()
	mustSet(t, tbl, Route{Host: "*.example", Mode: Passthrough, Backend: "127.0.0.1:1"})
	mustSet(t, tbl, Route{Host: "*.deep.example", Mode: Passthrough, Backend: "127.0.0.1:2"})
	mustSet(t, tbl, Route{Host: "exact.example", Mode: Terminate})

	if r, _ := tbl.Lookup("exact.example"); r.Mode != Terminate {
		t.Errorf("an exact route lost to a wildcard: got %+v", r)
	}
	if r, _ := tbl.Lookup("a.deep.example"); r.Backend != "127.0.0.1:2" {
		t.Errorf("the longer wildcard lost: got %+v", r)
	}
	if r, _ := tbl.Lookup("a.example"); r.Backend != "127.0.0.1:1" {
		t.Errorf("the shorter wildcard did not match: got %+v", r)
	}
}

// "Is this hostname claimed" is the question a service wizard has to ask,
// because "is this port free" fails for all five services -- addy took 443 at
// install time.
func TestSetRefusesAClaimedHostname(t *testing.T) {
	tbl := NewTable()
	mustSet(t, tbl, Route{Host: "vault.example", Mode: Proxy, Backend: "127.0.0.1:8222"})

	err := tbl.Set(Route{Host: "vault.example", Mode: Terminate})
	if !errors.Is(err, ErrHostClaimed) {
		t.Fatalf("Set(duplicate) = %v, want ErrHostClaimed", err)
	}
	// Re-setting the IDENTICAL route is not a conflict: an installer that is
	// re-run must not fail on its own previous success.
	if err := tbl.Set(Route{Host: "vault.example", Mode: Proxy, Backend: "127.0.0.1:8222"}); err != nil {
		t.Errorf("Set(identical) = %v, want nil; re-running must be safe", err)
	}
}

func TestSetRefusesAWildcardThatWouldShadowAnExactRoute(t *testing.T) {
	tbl := NewTable()
	mustSet(t, tbl, Route{Host: "vault.example", Mode: Proxy, Backend: "127.0.0.1:8222"})

	err := tbl.Set(Route{Host: "*.example", Mode: Passthrough, Backend: "127.0.0.1:8443"})
	if !errors.Is(err, ErrHostClaimed) {
		t.Fatalf("a shadowing wildcard was accepted: %v", err)
	}
}

func TestSetRejectsRoutesTheDoorCouldNotUse(t *testing.T) {
	cases := []struct {
		name  string
		route Route
	}{
		{"no hostname", Route{Mode: Terminate}},
		{"unknown mode", Route{Host: "a.example", Mode: "elsewhere", Backend: "127.0.0.1:1"}},
		{"proxy with no backend", Route{Host: "a.example", Mode: Proxy}},
		{"passthrough with no backend", Route{Host: "a.example", Mode: Passthrough}},
		{"terminate with a backend", Route{Host: "a.example", Mode: Terminate, Backend: "127.0.0.1:1"}},
		{"backend that is not host:port", Route{Host: "a.example", Mode: Proxy, Backend: "127.0.0.1"}},
		{"an IP literal", Route{Host: "127.0.0.1", Mode: Terminate}},
		{"a wildcard that is not leftmost", Route{Host: "*.a*.example", Mode: Terminate}},
		{"http80 that is not host:port", Route{Host: "a.example", Mode: Terminate, HTTP80: "nope"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := tblFor().Set(c.route); err == nil {
				t.Errorf("Set accepted %s", c.name)
			}
		})
	}
}

func tblFor() *Table { return NewTable() }

func TestHostnamesAreNormalisedOnce(t *testing.T) {
	tbl := NewTable()
	mustSet(t, tbl, Route{Host: "  ADDY.Example.  ", Mode: Terminate})

	hosts := tbl.Hosts()
	if len(hosts) != 1 || hosts[0] != "addy.example" {
		t.Fatalf("Hosts() = %v, want [addy.example]", hosts)
	}
	if _, ok := tbl.Lookup("addy.example"); !ok {
		t.Error("the normalised name does not look up")
	}
	// The un-normalised spelling must resolve to the same entry, or an
	// allowlist has two doors and only one of them is guarded.
	if _, ok := tbl.Lookup("ADDY.EXAMPLE."); !ok {
		t.Error("the original spelling does not look up")
	}
}

func TestDeleteIsIdempotent(t *testing.T) {
	tbl := NewTable()
	mustSet(t, tbl, Route{Host: "a.example", Mode: Terminate})
	mustSet(t, tbl, Route{Host: "*.b.example", Mode: Passthrough, Backend: "127.0.0.1:1"})

	tbl.Delete("a.example")
	tbl.Delete("a.example")
	tbl.Delete("*.b.example")
	tbl.Delete("never.there")

	if hosts := tbl.Hosts(); len(hosts) != 0 {
		t.Errorf("Hosts() = %v after deleting everything", hosts)
	}
	if err := tbl.Decide(context.Background(), "a.example"); !errors.Is(err, ErrNotConfigured) {
		t.Error("a deleted host is still certifiable")
	}
}

// Run with -race. An admin edits the table while TLS handshakes read it; this
// is the access pattern the RWMutex exists for, so it is exercised rather than
// asserted in a comment.
func TestConcurrentEditsDuringLookups(t *testing.T) {
	tbl := NewTable()
	mustSet(t, tbl, Route{Host: "stable.example", Mode: Terminate})

	var wg sync.WaitGroup
	stop := make(chan struct{})

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					tbl.Lookup("stable.example")
					_ = tbl.Decide(context.Background(), "churn.example")
					tbl.Hosts()
				}
			}
		}()
	}
	for i := 0; i < 200; i++ {
		_ = tbl.Set(Route{Host: "churn.example", Mode: Proxy, Backend: "127.0.0.1:9"})
		tbl.Delete("churn.example")
	}
	close(stop)
	wg.Wait()

	if _, ok := tbl.Lookup("stable.example"); !ok {
		t.Error("the stable route did not survive concurrent edits")
	}
}

func TestRefusalNamesTheHostWithoutInterpolatingItIntoAnything(t *testing.T) {
	tbl := NewTable()
	err := tbl.Decide(context.Background(), "attacker-chosen.example")
	if err == nil || !strings.Contains(err.Error(), "attacker-chosen.example") {
		t.Fatalf("the refusal does not name the host: %v", err)
	}
}

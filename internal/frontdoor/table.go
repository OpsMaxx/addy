package frontdoor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
)

// Mode is what the front door does with a connection for a given hostname.
//
// Note there are three modes but only TWO decisions at the SNI layer: either we
// terminate TLS or we do not. Proxying happens after termination, decided by an
// http.Handler. Treating proxy and terminate as peers at the peek is how a
// router ends up with a code path that tries to reverse-proxy raw TLS bytes.
type Mode string

const (
	// Terminate: addy's own mux -- the portal, the paste service, the API.
	Terminate Mode = "terminate"
	// Proxy: TLS ends here, the decrypted HTTP goes to a loopback backend.
	Proxy Mode = "proxy"
	// Passthrough: the bytes are spliced untouched to a loopback backend.
	// This exists for frps vhost_https, which does its own SNI vhosting and
	// therefore cannot be reverse-proxied by an HTTP server at all.
	Passthrough Mode = "passthrough"
)

// Route is one hostname's disposition.
type Route struct {
	Host    string // exact ("a.example") or wildcard ("*.example")
	Mode    Mode
	Backend string // host:port on loopback; empty if and only if Mode is Terminate
	HTTP80  string // optional host:port for plain-HTTP vhosting; empty means redirect
}

// Table is the routing table and the on-demand TLS allowlist at the same time.
//
// THEY ARE ONE OBJECT ON PURPOSE. A hostname is certifiable exactly when an
// admin configured a route for it. Two structures holding "which names are ours"
// is how one of them ends up stale, and the one that ends up stale is always the
// permissive one.
//
// A map behind an RWMutex, not a sync.Map: reads happen on every TLS handshake
// and writes happen when a human clicks a button, which is the access pattern
// RWMutex is for. sync.Map would buy nothing and cost type safety.
type Table struct {
	mu       sync.RWMutex
	exact    map[string]Route
	wildcard []Route // sorted longest-suffix-first, so the first match is the most specific
}

func NewTable() *Table {
	return &Table{exact: make(map[string]Route)}
}

var (
	// ErrNotConfigured is what Decide returns for a hostname nobody configured.
	// It is the refusal that stops this box being an open certificate-issuance
	// relay for anyone who points a DNS record at its address.
	ErrNotConfigured = errors.New("hostname is not configured on this instance")

	ErrHostClaimed = errors.New("hostname is already claimed on this instance")
	ErrBadRoute    = errors.New("route is not usable")
)

// normalise lowercases, strips the trailing dot a fully-qualified name may
// carry, and strips a port if one came along with a Host header.
//
// A SNI value arrives from an anonymous client, and "Example.COM." and
// "example.com" must not be two different entries in an allowlist.
func normalise(host string) string {
	host = strings.TrimSpace(host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(host, ".")
	return strings.ToLower(host)
}

// Lookup resolves a hostname to its route. Exact matches win over wildcards,
// and among wildcards the longest suffix wins.
func (t *Table) Lookup(host string) (Route, bool) {
	host = normalise(host)
	if host == "" {
		return Route{}, false
	}

	t.mu.RLock()
	defer t.mu.RUnlock()

	if r, ok := t.exact[host]; ok {
		return r, true
	}
	for _, w := range t.wildcard {
		if matchWildcard(w.Host, host) {
			return w, true
		}
	}
	return Route{}, false
}

// matchWildcard implements exactly one level, the way a TLS wildcard
// certificate does: "*.example.com" matches "a.example.com" and does NOT match
// "example.com" or "a.b.example.com".
//
// The looser reading -- a suffix match -- is the one people write by accident,
// and it silently widens the allowlist to every depth of subdomain under a
// name, which is the thing the allowlist exists to bound.
func matchWildcard(pattern, host string) bool {
	suffix, ok := strings.CutPrefix(pattern, "*.")
	if !ok {
		return false
	}
	label, rest, found := strings.Cut(host, ".")
	return found && label != "" && rest == suffix
}

func validate(r Route) error {
	host := normalise(r.Host)
	if host == "" {
		return fmt.Errorf("%w: empty hostname", ErrBadRoute)
	}
	// An IP literal can never have a publicly trusted certificate from an ACME
	// CA, so a route for one would be an entry in the allowlist that can only
	// ever fail issuance. Rejecting it here keeps it out of the metrics too.
	if net.ParseIP(strings.TrimPrefix(host, "*.")) != nil {
		return fmt.Errorf("%w: %s is an IP address", ErrBadRoute, host)
	}
	if strings.Contains(strings.TrimPrefix(host, "*."), "*") {
		return fmt.Errorf("%w: %s has a wildcard that is not the leftmost label", ErrBadRoute, host)
	}
	switch r.Mode {
	case Terminate:
		if r.Backend != "" {
			return fmt.Errorf("%w: %s terminates here and cannot have a backend", ErrBadRoute, host)
		}
	case Proxy, Passthrough:
		if r.Backend == "" {
			return fmt.Errorf("%w: %s is %s and needs a backend", ErrBadRoute, host, r.Mode)
		}
		if _, _, err := net.SplitHostPort(r.Backend); err != nil {
			return fmt.Errorf("%w: %s backend %q is not host:port", ErrBadRoute, host, r.Backend)
		}
	default:
		return fmt.Errorf("%w: unknown mode %q", ErrBadRoute, r.Mode)
	}
	if r.HTTP80 != "" {
		if _, _, err := net.SplitHostPort(r.HTTP80); err != nil {
			return fmt.Errorf("%w: %s http80 %q is not host:port", ErrBadRoute, host, r.HTTP80)
		}
	}
	return nil
}

// Set adds or replaces a route.
//
// The preflight question a service wizard must ask is "is this hostname
// CLAIMED", not "is this port free" -- every port a wizard could ask about is
// already held by addy, so the port question fails for all five services and
// answers nothing. This is where the real question is enforced.
func (t *Table) Set(r Route) error {
	if err := validate(r); err != nil {
		return err
	}
	r.Host = normalise(r.Host)

	t.mu.Lock()
	defer t.mu.Unlock()

	if existing, ok := t.exact[r.Host]; ok && existing != r {
		return fmt.Errorf("%w: %s", ErrHostClaimed, r.Host)
	}
	for _, w := range t.wildcard {
		if w.Host == r.Host && w != r {
			return fmt.Errorf("%w: %s", ErrHostClaimed, r.Host)
		}
	}

	if strings.HasPrefix(r.Host, "*.") {
		// A wildcard that would shadow an exact route already present is
		// refused, so the more specific entry cannot be quietly overtaken by a
		// broader one added later.
		for host := range t.exact {
			if matchWildcard(r.Host, host) {
				return fmt.Errorf("%w: %s would shadow %s", ErrHostClaimed, r.Host, host)
			}
		}
		t.wildcard = append(t.wildcard, r)
		// Longest pattern first, so Lookup's first match is the most specific.
		slices.SortFunc(t.wildcard, func(a, b Route) int {
			return len(b.Host) - len(a.Host)
		})
		return nil
	}
	t.exact[r.Host] = r
	return nil
}

// Delete removes a route. Removing something absent is not an error: an admin
// deleting a host twice has got what they wanted both times.
func (t *Table) Delete(host string) {
	host = normalise(host)
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.exact, host)
	t.wildcard = slices.DeleteFunc(t.wildcard, func(r Route) bool { return r.Host == host })
}

// Hosts returns every configured hostname, sorted, for certmagic's ManageSync
// and for the portal's status view.
func (t *Table) Hosts() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]string, 0, len(t.exact)+len(t.wildcard))
	for host := range t.exact {
		out = append(out, host)
	}
	for _, w := range t.wildcard {
		out = append(out, w.Host)
	}
	slices.Sort(out)
	return out
}

// Decide is certmagic's OnDemand.DecisionFunc.
//
// THIS FUNCTION IS THE CONTROL. An on-demand TLS config whose DecisionFunc
// returns nil unconditionally turns the box into an open certificate-issuance
// relay: any stranger points a DNS record at this address, every connection
// starts an ACME order, and the account trips the CA's rate limit and stops
// issuing for the names that are real. So the default is refusal and the
// allowlist is the routing table.
//
// It runs inside a live TLS handshake, so it does a map read under an RLock and
// nothing else -- no I/O, no network, no database.
func (t *Table) Decide(ctx context.Context, name string) error {
	r, ok := t.Lookup(name)
	if !ok {
		// The name is attacker-chosen, so it is not formatted into anything
		// with unbounded cardinality -- a metric label keyed on it is its own
		// outage. It goes in the error, which is rate-limited by the caller.
		return fmt.Errorf("%w: %s", ErrNotConfigured, name)
	}
	if r.Mode == Passthrough {
		// A passthrough name's handshake is never terminated here, so on-demand
		// issuance can never legitimately fire for it. If it does, something is
		// misrouted, and obtaining a certificate for a name we do not serve
		// would hide the misrouting behind a working handshake.
		return fmt.Errorf("%w: %s is passthrough", ErrNotConfigured, name)
	}
	return nil
}

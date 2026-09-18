package frontdoor

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Why TLS is not working, in words an operator can act on.
//
// THE PROBLEM THIS SOLVES, found by running a real instance: when certificate
// issuance is stuck, the only thing anybody sees is
//
//	http: TLS handshake error from 1.2.3.4: timed out waiting to load
//	certificate for relay.example
//
// which is reported from the CLIENT side, names no cause, and reads like a
// broken TLS configuration. The actual reason -- the CA answered 503, DNS is
// wrong, port 80 is firewalled, the rate limit is spent -- is in certmagic's
// structured log among a hundred other lines, and the operator has no reason
// to look there rather than at their own config.
//
// So the last failure is kept, and `addy selftest` reports it. One value, not
// a history: the question is "why is this not working NOW", and a list of
// every transient retry buries the answer it is supposed to give.

// ACMEStatus is the last thing issuance did.
type ACMEStatus struct {
	mu sync.RWMutex

	lastError    string
	lastErrorAt  time.Time
	lastObtained string
	obtainedAt   time.Time
	attempts     int
}

// Observe returns an event handler to chain into certmagic.
//
// It NEVER returns an error. certmagic treats a non-nil return from OnEvent as
// a reason to abort issuance for some events, so a status recorder that failed
// would stop the thing it is reporting on -- which is the failure mode the
// export hook's own test was written for.
func (s *ACMEStatus) Observe(next func(context.Context, string, map[string]any) error) func(context.Context, string, map[string]any) error {
	return func(ctx context.Context, event string, data map[string]any) error {
		switch event {
		case "cert_obtained":
			s.mu.Lock()
			s.lastObtained, _ = data["identifier"].(string)
			s.obtainedAt = time.Now()
			s.lastError = ""
			s.mu.Unlock()
		case "cert_failed":
			s.mu.Lock()
			s.attempts++
			name, _ := data["identifier"].(string)
			reason := "no reason given"
			if err, ok := data["error"].(error); ok && err != nil {
				reason = err.Error()
			} else if text, ok := data["error"].(string); ok && text != "" {
				reason = text
			}
			s.lastError = fmt.Sprintf("%s: %s", name, reason)
			s.lastErrorAt = time.Now()
			s.mu.Unlock()
		}
		if next != nil {
			// The chained handler's error is swallowed for the same reason
			// this one never produces its own.
			_ = next(ctx, event, data)
		}
		return nil
	}
}

// Report is what an operator is told. Empty when nothing has gone wrong.
func (s *ACMEStatus) Report() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.lastObtained != "" && s.lastError == "" {
		return fmt.Sprintf("certificate for %s obtained %s ago",
			s.lastObtained, time.Since(s.obtainedAt).Round(time.Second))
	}
	if s.lastError == "" {
		return ""
	}
	return fmt.Sprintf(`certificate issuance has failed %d time(s); the most recent, %s ago:

  %s

Until it succeeds every HTTPS connection fails with "timed out waiting to load
certificate", which is this, not a TLS misconfiguration. The usual causes, in
the order worth checking: port 80 unreachable from the internet, DNS not
pointing here, or the CA refusing -- a 503 saying "Service busy" is the CA's
problem and clears on its own`,
		s.attempts, time.Since(s.lastErrorAt).Round(time.Second), s.lastError)
}

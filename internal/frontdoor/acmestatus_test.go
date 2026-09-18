package frontdoor

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// What an operator is told when TLS does not work.
//
// The symptom they actually see is reported from the client side -- "timed out
// waiting to load certificate" -- names no cause, and reads like a broken TLS
// configuration. These check that the real reason survives to somewhere they
// will find it.

func TestItNamesTheReasonIssuanceFailed(t *testing.T) {
	s := &ACMEStatus{}
	handler := s.Observe(nil)

	err := handler(context.Background(), "cert_failed", map[string]any{
		"identifier": "relay.example",
		"error":      errors.New("HTTP 503 rateLimited - Service busy; retry later"),
	})
	if err != nil {
		t.Fatalf("Observe returned %v; it must never abort issuance", err)
	}

	report := s.Report()
	for _, want := range []string{"relay.example", "Service busy", "timed out waiting to load"} {
		if !strings.Contains(report, want) {
			t.Errorf("the report does not mention %q:\n%s", want, report)
		}
	}
	// The usual causes, in the order worth checking. A message that only says
	// "it failed" sends somebody to their TLS config, which is the one place
	// the problem is not.
	if !strings.Contains(report, "port 80") {
		t.Error("the report does not say where to look first")
	}
}

func TestSuccessClearsTheComplaint(t *testing.T) {
	s := &ACMEStatus{}
	handler := s.Observe(nil)
	_ = handler(context.Background(), "cert_failed", map[string]any{
		"identifier": "relay.example", "error": errors.New("boom"),
	})
	_ = handler(context.Background(), "cert_obtained", map[string]any{"identifier": "relay.example"})

	report := s.Report()
	if strings.Contains(report, "failed") {
		t.Fatalf("a success left the failure standing:\n%s", report)
	}
	if !strings.Contains(report, "obtained") {
		t.Fatalf("a success says nothing:\n%s", report)
	}
}

func TestNothingToSayIsSilence(t *testing.T) {
	// An instance that has never tried -- `-dev`, or one with no domain -- must
	// not produce a warning about a thing that is not wrong.
	if got := (&ACMEStatus{}).Report(); got != "" {
		t.Fatalf("a fresh instance reported %q", got)
	}
}

// certmagic treats a non-nil return from OnEvent as a reason to abort issuance
// for some events. A status recorder that failed would stop the thing it is
// reporting on.
func TestItNeverAbortsIssuance(t *testing.T) {
	s := &ACMEStatus{}
	chained := s.Observe(func(context.Context, string, map[string]any) error {
		return errors.New("the exporter is unhappy")
	})
	for _, event := range []string{"cert_obtained", "cert_failed", "cert_obtaining", "anything"} {
		if err := chained(context.Background(), event, map[string]any{}); err != nil {
			t.Errorf("event %q returned %v", event, err)
		}
	}
}

func TestItStillCallsTheHandlerItWraps(t *testing.T) {
	// The export hook reloads TURN's certificate on renewal. A status recorder
	// that swallowed the event would kill TURNS sixty days after install.
	s := &ACMEStatus{}
	called := 0
	chained := s.Observe(func(context.Context, string, map[string]any) error {
		called++
		return nil
	})
	_ = chained(context.Background(), "cert_obtained", map[string]any{"identifier": "x"})
	if called != 1 {
		t.Fatalf("the wrapped handler was called %d times", called)
	}
}

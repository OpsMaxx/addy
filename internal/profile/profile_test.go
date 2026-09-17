package profile

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// THE DEFAULT IS T0. A key not in the allowlist is secret, full stop. A
// blocklist would mean every new setting is public until somebody remembers to
// classify it, and the one nobody remembers is the one that mattered.
func TestAnyFieldNotOnTheAllowlistIsRefused(t *testing.T) {
	for _, body := range []string{
		`{"sshPrivateKey":"-----BEGIN..."}`,
		`{"vaultMasterPassword":"hunter2"}`,
		`{"theme":"dark","somethingNew":true}`,
	} {
		_, err := Validate([]byte(body))
		if !errors.Is(err, ErrUnknownField) {
			t.Errorf("Validate(%s) = %v, want ErrUnknownField", body, err)
		}
	}
}

// `modules` is the specific one security review moved out of T2, and it is
// worth its own test because it was ON this list once. It is a capability
// switch, not a preference: a hostile server serving a plaintext profile could
// otherwise enable the entire privileged surface on every device in the
// account.
func TestModulesIsNotInTheProfile(t *testing.T) {
	if slices.Contains(Names(), "modules") {
		t.Fatal("modules is in the T2 allowlist; it is a capability switch and belongs in T0")
	}
	if _, err := Validate([]byte(`{"modules":{"cicdTrigger":true}}`)); !errors.Is(err, ErrUnknownField) {
		t.Fatalf("Validate(modules) = %v, want ErrUnknownField", err)
	}
}

// NO KEY WHOSE ABSENCE GRANTS SOMETHING MAY BE HERE. OpsMaxx merges
// saved-over-default, so several settings read absence as "on" --
// localTerminalEnabled is the sharp one. Against that polarity an OMISSION is
// an attack, so the rule is not "every key is classified" but "no
// capability-gating key is in T2".
func TestNoCapabilityGatingKeyIsInTheProfile(t *testing.T) {
	// Named rather than pattern-matched, because the point is that a person
	// reading this list meets the polarity trap.
	forbidden := []string{
		"localTerminalEnabled",
		"modules",
		"aiPolicy",
		"allowEscalation",
		"trustedHosts",
		"credentialProxyEnabled",
	}
	for _, name := range forbidden {
		if slices.Contains(Names(), name) {
			t.Errorf("%q is in the T2 allowlist; absence of it grants something, so plaintext is an attack", name)
		}
	}
}

// Scalars and enums only. A plaintext profile from a hostile server is
// untrusted input feeding a client-side parser.
func TestOnlyScalarsAndEnumsAreAccepted(t *testing.T) {
	for _, body := range []string{
		`{"theme":{"nested":"object"}}`,
		`{"theme":["a","list"]}`,
		`{"terminalFontSize":"twelve"}`,
		`{"compactDensity":"yes"}`,
		`{"terminalFontSize":12.5}`,
	} {
		if _, err := Validate([]byte(body)); !errors.Is(err, ErrWrongType) && !errors.Is(err, ErrOutOfRange) {
			t.Errorf("Validate(%s) = %v, want a type or range refusal", body, err)
		}
	}
}

// Every value is validated for RANGE, because a hostile server can set any
// number it likes and the client will render it.
func TestValuesOutsideTheirRangeAreRefused(t *testing.T) {
	for _, body := range []string{
		`{"terminalFontSize":0}`,
		`{"terminalFontSize":9999}`,
		`{"terminalFontSize":-1}`,
		`{"dbSchemaWidth":1}`,
		`{"dbSchemaWidth":100000}`,
		`{"theme":"chartreuse"}`,
		`{"terminalScheme":"../../etc/passwd"}`,
	} {
		if _, err := Validate([]byte(body)); !errors.Is(err, ErrOutOfRange) {
			t.Errorf("Validate(%s) = %v, want ErrOutOfRange", body, err)
		}
	}
}

func TestAValidProfileRoundTrips(t *testing.T) {
	body := `{"theme":"dark","terminalFontSize":14,"compactDensity":true,"terminalScheme":"nord"}`
	out, err := Validate([]byte(body))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if out["theme"] != "dark" {
		t.Errorf("theme = %v", out["theme"])
	}
	if out["terminalFontSize"] != int64(14) {
		t.Errorf("terminalFontSize = %#v, want int64(14)", out["terminalFontSize"])
	}
	if out["compactDensity"] != true {
		t.Errorf("compactDensity = %v", out["compactDensity"])
	}
}

// A plaintext field an attacker can grow is a covert channel with a quota
// attached.
func TestAnOversizedProfileIsRefused(t *testing.T) {
	big := `{"theme":"` + strings.Repeat("a", MaxBytes) + `"}`
	if _, err := Validate([]byte(big)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Validate(oversized) = %v, want ErrTooLarge", err)
	}
}

// Trailing data after the document is the same class of hazard as trailing
// bytes in the canonical encoding: two parsers disagreeing about where the
// value ends.
func TestTrailingDataIsRefused(t *testing.T) {
	if _, err := Validate([]byte(`{"theme":"dark"} {"theme":"light"}`)); err == nil {
		t.Fatal("Validate accepted trailing data")
	}
}

// The allowlist itself has to be well-formed, or a field could be unreachable
// or accept anything.
func TestTheAllowlistIsCoherent(t *testing.T) {
	seen := map[string]bool{}
	for _, f := range Allowed {
		if seen[f.Name] {
			t.Errorf("duplicate field %q", f.Name)
		}
		seen[f.Name] = true

		switch f.Kind {
		case KindInt:
			if f.Min >= f.Max {
				t.Errorf("%s has an empty range %d..%d", f.Name, f.Min, f.Max)
			}
			if len(f.Values) != 0 {
				t.Errorf("%s is an int with enum values", f.Name)
			}
		case KindEnum:
			if len(f.Values) < 2 {
				t.Errorf("%s is an enum with %d values", f.Name, len(f.Values))
			}
			for _, v := range f.Values {
				if v == "" {
					t.Errorf("%s has an empty enum value", f.Name)
				}
			}
		case KindBool:
			if f.Min != 0 || f.Max != 0 || len(f.Values) != 0 {
				t.Errorf("%s is a bool with range or enum constraints", f.Name)
			}
		}
	}

	// Every field must actually accept its own valid values, or the allowlist
	// lists something nobody can set.
	for _, f := range Allowed {
		var body string
		switch f.Kind {
		case KindBool:
			body = fmt.Sprintf(`{%q:true}`, f.Name)
		case KindInt:
			body = fmt.Sprintf(`{%q:%d}`, f.Name, f.Min)
		case KindEnum:
			body = fmt.Sprintf(`{%q:%q}`, f.Name, f.Values[0])
		}
		if _, err := Validate([]byte(body)); err != nil {
			t.Errorf("the allowlist rejects its own valid value for %s: %v", f.Name, err)
		}
	}
}

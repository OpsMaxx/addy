// Package profile is the T2 public profile: the small set of preferences addy
// stores in PLAINTEXT, deliberately.
//
// WHY ANY PLAINTEXT AT ALL. A brand-new device should be able to pull a
// usable-looking OpsMaxx before any pairing has happened -- the right theme, the
// right terminal font -- rather than presenting defaults and then rearranging
// itself once the user finds their phrase. That is the entire justification, and
// it is the reason the list is as short as it is.
//
// WHO MAY READ IT, specified rather than assumed. An earlier draft said a user
// gets their layout back "from their password alone", which described nothing:
// there is no account password anywhere in this system. The answer is: AN
// AUTHENTICATED DEVICE OF THAT ACCOUNT, and nobody else. A world-readable
// profile would leak the estate's technology profile -- which modules, which
// terminal tooling -- to anyone who guessed an account id, and inventing a
// password to protect it would add an unanalysed server-side brute-force target
// to a design that deliberately has none.
package profile

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Kind is what a T2 value is allowed to be.
//
// SCALARS AND ENUMS ONLY. A plaintext profile from a hostile server is
// untrusted input that feeds a client-side parser, so every value is validated
// for range and shape on arrival. Nothing here may be a nested object, a list of
// arbitrary shape, or anything that needs a schema to interpret.
type Kind uint8

const (
	KindBool Kind = iota
	KindInt
	KindEnum
)

// Field is one allowlisted preference.
type Field struct {
	Name   string
	Kind   Kind
	Min    int      // KindInt
	Max    int      // KindInt
	Values []string // KindEnum
}

// Allowed is the T2 allowlist, and it is an ALLOWLIST rather than a blocklist.
//
// THE DEFAULT IS T0. A key that is not in this table is secret, full stop. That
// is the only version of this rule that survives a year of feature work: a
// blocklist means every new setting is public until somebody remembers to
// classify it, and the one nobody remembers is the one that mattered.
//
// TWO THINGS THAT ARE DELIBERATELY ABSENT.
//
// `modules` was on an early version of this list and security review moved it
// to T0. It is a CAPABILITY SWITCH, not a preference: a hostile server serving a
// plaintext profile could enable the entire privileged surface on every device
// in the account. OpsMaxx already has a rule that an upgrade is not consent;
// letting a plaintext profile do what an upgrade may not would invert it.
//
// AND NO KEY WHOSE ABSENCE GRANTS SOMETHING MAY BE HERE. OpsMaxx merges
// saved-over-default, so several settings read absence as "on" --
// localTerminalEnabled is the sharp one. Against that polarity an OMISSION is an
// attack, so the rule is not merely "every key is classified" but "no
// capability-gating key is in T2", and the polarity trap is named so the next
// person to add a field meets it.
var Allowed = []Field{
	{Name: "theme", Kind: KindEnum, Values: []string{"light", "dark", "system"}},
	{Name: "terminalFontSize", Kind: KindInt, Min: 8, Max: 32},
	{Name: "terminalScheme", Kind: KindEnum, Values: []string{
		"default", "solarized-dark", "solarized-light", "nord", "dracula", "gruvbox", "custom",
	}},
	{Name: "compactDensity", Kind: KindBool},
	{Name: "dbSchemaWidth", Kind: KindInt, Min: 120, Max: 2000},
	{Name: "dbEditorHeight", Kind: KindInt, Min: 80, Max: 2000},
	{Name: "cicdStepsWidth", Kind: KindInt, Min: 120, Max: 2000},
	{Name: "cicdDetailHeight", Kind: KindInt, Min: 80, Max: 2000},
	{Name: "showMonitorStrip", Kind: KindBool},
	{Name: "closeTabOnShellExit", Kind: KindBool},
	{Name: "switchHiddenWorkspaces", Kind: KindBool},
}

// MaxBytes bounds a stored profile. It is eleven scalars; anything larger is
// somebody using it as storage, and a plaintext field an attacker can grow is a
// covert channel with a quota attached.
const MaxBytes = 4 << 10

var (
	ErrUnknownField = errors.New("profile: that field is not in the T2 allowlist, so it is secret")
	ErrWrongType    = errors.New("profile: that value is the wrong type for its field")
	ErrOutOfRange   = errors.New("profile: that value is outside the field's range")
	ErrTooLarge     = errors.New("profile: the profile is too large")
)

func field(name string) (Field, bool) {
	for _, f := range Allowed {
		if f.Name == name {
			return f, true
		}
	}
	return Field{}, false
}

// Validate checks a profile on arrival.
//
// Called on BOTH sides, and that is not belt and braces. The server validates so
// a device cannot store something another device's parser will choke on; the
// client validates because the server is the party this whole design assumes is
// hostile, and a plaintext profile is the one thing it can rewrite freely.
func Validate(raw []byte) (map[string]any, error) {
	if len(raw) > MaxBytes {
		return nil, fmt.Errorf("%w: %d bytes, limit %d", ErrTooLarge, len(raw), MaxBytes)
	}

	var in map[string]any
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	// Numbers as json.Number rather than float64: a terminal font size that
	// arrives as 12.000000000000002 and is silently truncated is a value nobody
	// set, and float64 cannot represent every int64 exactly.
	dec.UseNumber()
	if err := dec.Decode(&in); err != nil {
		return nil, fmt.Errorf("profile: %w", err)
	}
	if dec.More() {
		return nil, errors.New("profile: trailing data after the profile")
	}

	out := make(map[string]any, len(in))
	for name, v := range in {
		f, ok := field(name)
		if !ok {
			// Named in the error, because the fix is to classify it rather than
			// to widen the allowlist by reflex.
			return nil, fmt.Errorf("%w: %q", ErrUnknownField, name)
		}
		clean, err := check(f, v)
		if err != nil {
			return nil, err
		}
		out[name] = clean
	}
	return out, nil
}

func check(f Field, v any) (any, error) {
	switch f.Kind {
	case KindBool:
		b, ok := v.(bool)
		if !ok {
			return nil, fmt.Errorf("%w: %s wants a bool", ErrWrongType, f.Name)
		}
		return b, nil

	case KindInt:
		n, ok := v.(json.Number)
		if !ok {
			return nil, fmt.Errorf("%w: %s wants a number", ErrWrongType, f.Name)
		}
		i, err := n.Int64()
		if err != nil {
			return nil, fmt.Errorf("%w: %s wants a whole number", ErrWrongType, f.Name)
		}
		if i < int64(f.Min) || i > int64(f.Max) {
			return nil, fmt.Errorf("%w: %s is %d, allowed %d to %d", ErrOutOfRange, f.Name, i, f.Min, f.Max)
		}
		return i, nil

	case KindEnum:
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("%w: %s wants a string", ErrWrongType, f.Name)
		}
		if !slices.Contains(f.Values, s) {
			return nil, fmt.Errorf("%w: %s is %q, allowed %v", ErrOutOfRange, f.Name, s, f.Values)
		}
		return s, nil
	}
	return nil, fmt.Errorf("profile: %s has an unknown kind", f.Name)
}

// Names lists the allowlist, for the test that pins it against the client's own
// settings type.
func Names() []string {
	out := make([]string, 0, len(Allowed))
	for _, f := range Allowed {
		out = append(out, f.Name)
	}
	slices.Sort(out)
	return out
}

package main

import (
	"os"
	"regexp"
	"testing"
)

// A FLAG WITH A DEFAULT CANNOT ALSO READ THE ENVIRONMENT, and the failure is
// silent in the direction that matters: the variable is set, read, found, and
// discarded, so the operator sees their setting ignored with nothing logged.
//
// envDefault leaves a value alone once something has set it — that is how a
// flag beats a variable. But `flag` sets every value it parses, default
// included, so by the time envDefault runs it cannot tell `-signup open` from
// the default `invite` that nobody asked for. Declaring the flag with "" and
// putting the default in the envDefault call restores the intended order:
// flag, then environment, then default.
//
// This shipped. `-signup` took its default here, so ADDY_SIGNUP did nothing
// and a relay configured for open signup stayed invite-only. `-data-dir` had
// it too, and both deployments that ship with this repo set ADDY_DATA_DIR.
// They agreed with the default, so nothing broke and nothing complained.
//
// The test reads the source rather than the behaviour because the behaviour
// is only wrong when the two disagree, which is exactly the case no existing
// test set up.
func TestEveryEnvironmentFlagDefersItsDefault(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("reading main.go: %v", err)
	}

	// Which config fields are read from the environment.
	fromEnv := map[string]string{}
	for _, m := range regexp.MustCompile(
		`envDefault\(&cfg\.(\w+), "(\w+)"`).FindAllStringSubmatch(string(src), -1) {
		fromEnv[m[1]] = m[2]
	}
	if len(fromEnv) < 5 {
		t.Fatalf("the parser is wrong, not the code: found %d environment-backed fields", len(fromEnv))
	}

	// Which of those are declared with a default the flag package will set.
	declared := regexp.MustCompile(`fs\.StringVar\(&cfg\.(\w+), "([\w-]+)", ("[^"]*"|[^,]+),`)
	found := 0
	for _, m := range declared.FindAllStringSubmatch(string(src), -1) {
		field, flagName, def := m[1], m[2], m[3]
		env, ok := fromEnv[field]
		if !ok {
			continue
		}
		found++
		if def != `""` {
			t.Errorf("-%s is declared with the default %s, so %s is read and thrown away.\n"+
				"Declare the flag with \"\" and move the default into the envDefault call.",
				flagName, def, env)
		}
	}
	if found < 5 {
		t.Fatalf("the parser is wrong, not the code: matched %d flag declarations", found)
	}
}

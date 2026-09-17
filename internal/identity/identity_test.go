package identity

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// THE TEST THIS PACKAGE EXISTS TO PASS.
//
// A device's identity must not be derived from the host. Not from the
// hostname, not from the OS username, not from a MAC address, a disk serial or
// a machine-id. The failure this prevents is not a crash: it is a device
// identity that can be correlated back to a physical machine by anyone holding
// the metadata, which is precisely what the threat model promises cannot be
// done.
//
// It is enforced by import, because that is the only form that survives
// somebody being helpful. "Let's put the hostname in the name so it is friendlier"
// is a reasonable-sounding change that quietly breaks the guarantee, and a
// comment asking people not to do it does not stop it.
func TestNothingHereReadsTheHost(t *testing.T) {
	forbidden := map[string]string{
		"os":      "reads hostname, environment and user",
		"os/user": "reads the OS account",
		"net":     "reads interfaces and MAC addresses",
	}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}

	checked := 0
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		checked++
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		for _, imp := range file.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatalf("%s has an unparsable import %s", name, imp.Path.Value)
			}
			if why, bad := forbidden[path]; bad {
				t.Errorf("%s imports %q, which %s. A device identity must come from the CSPRNG and nowhere else",
					name, path, why)
			}
		}
	}
	if checked == 0 {
		t.Fatal("checked 0 files; the test is looking in the wrong place")
	}
}

// Two calls in the same environment must differ. If a name were host-derived it
// would be stable across calls, which is the observable symptom of the failure
// above.
func TestTwoDevicesOnOneMachineAreDifferent(t *testing.T) {
	seen := make(map[string]bool)
	const draws = 200
	for i := 0; i < draws; i++ {
		name, err := Pseudonym()
		if err != nil {
			t.Fatalf("Pseudonym: %v", err)
		}
		seen[name] = true
	}
	// 1.69M combinations, so 200 draws colliding more than a couple of times
	// means something is not random rather than that we were unlucky.
	if len(seen) < draws-2 {
		t.Errorf("%d draws produced only %d distinct names", draws, len(seen))
	}
}

var shape = regexp.MustCompile(`^[a-z]+-[a-z]+-[0-9]{2}$`)

// Every name is the same shape and the same length class. One that is
// sometimes brave-pylon-7 and sometimes brave-pylon-70 is harder to compare at
// a glance, and comparing at a glance is the whole job.
func TestEveryNameHasTheSameShape(t *testing.T) {
	for i := 0; i < 500; i++ {
		name, err := Pseudonym()
		if err != nil {
			t.Fatalf("Pseudonym: %v", err)
		}
		if !shape.MatchString(name) {
			t.Fatalf("name %q does not match adjective-noun-NN", name)
		}
	}
}

// The lists are shared with a TypeScript implementation that does not exist
// yet. These are the properties that implementation will also have to satisfy,
// written down now so it has something to be checked against rather than a
// description in a commit message.
func TestTheWordlistsAreUsableByASecondImplementation(t *testing.T) {
	for _, tc := range []struct {
		name string
		list []string
	}{
		{"adjectives", adjectives},
		{"nouns", nouns},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.list) < 100 {
				t.Errorf("%d entries; too few for a name to feel distinctive", len(tc.list))
			}
			// Sorted and unique, so two implementations index the same word for
			// the same number and a diff of the file is readable.
			if !slices.IsSorted(tc.list) {
				t.Error("the list is not sorted; two implementations could index it differently")
			}
			for i := 1; i < len(tc.list); i++ {
				if tc.list[i] == tc.list[i-1] {
					t.Errorf("duplicate entry %q, which skews the distribution", tc.list[i])
				}
			}
			for _, w := range tc.list {
				if w != strings.ToLower(w) {
					t.Errorf("%q is not lowercase", w)
				}
				if strings.ContainsAny(w, "-0123456789 ") {
					t.Errorf("%q contains a separator or digit, which makes the name ambiguous to parse", w)
				}
			}
		})
	}

	// No word in both lists. "coral-coral-41" reads as a mistake, and a user
	// who has to explain their device name has been let down by it.
	for _, a := range adjectives {
		if slices.Contains(nouns, a) {
			t.Errorf("%q is in both lists", a)
		}
	}
}

// Guard against the embed silently producing nothing, which would leave
// Pseudonym returning an error at runtime on a path nobody exercises.
func TestTheWordlistsActuallyEmbedded(t *testing.T) {
	if len(adjectives) == 0 || len(nouns) == 0 {
		t.Fatal("a wordlist is empty; the embed did not load")
	}
	for _, name := range []string{"adjectives.txt", "nouns.txt"} {
		if _, err := os.Stat(filepath.Join("wordlists", name)); err != nil {
			t.Errorf("wordlists/%s is missing: %v", name, err)
		}
	}
}

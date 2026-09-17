package repocheck

import (
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The release workflow is ratcheted, inherited from the sibling repo, which
// added its version after two bugs shipped that no other kind of test could
// have caught: a notes generator that was correct and a workflow that never
// called it, and an append that silently did nothing so every release for six
// versions had an empty body.
//
// Neither was a logic error. Both were shape errors in a YAML file nobody
// reads top to bottom, which is precisely what grows unreviewably when steps
// are added one at a time.
//
// So: every inline `run` step in the release job must be listed here with a
// line budget. Adding a step turns the build red until someone writes it down;
// growing one past its number does the same. `uses:`-only steps are exempt --
// they are a version pin and a parameter list, not a program.
//
// Every raise goes in with its reason, so the history of this map is the
// history of the workflow getting more complicated and someone noticing.
var ceiling = map[string]int{
	"Check the tag matches the version the binary reports": 12,
	"Build every target":              3,
	"Check the build is reproducible": 10,
	"Scan the binaries with ClamAV":   18,
	// 46: the notes carry an install line, the container reference, a
	// per-platform download table and a checksum table, and each of those is a
	// row of shell rather than a line of prose.
	"Build the release notes":                  46,
	"Verify the published notes, then publish": 20,
}

type workflow struct {
	Jobs map[string]struct {
		Steps []struct {
			Name string `yaml:"name"`
			Run  string `yaml:"run"`
			Uses string `yaml:"uses"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

func loadWorkflow(t *testing.T) workflow {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatalf("reading the release workflow: %v", err)
	}
	var wf workflow
	if err := yaml.Unmarshal(b, &wf); err != nil {
		t.Fatalf("parsing the release workflow: %v", err)
	}
	if len(wf.Jobs) == 0 {
		t.Fatal("parsed no jobs; the parser is wrong, not the workflow")
	}
	return wf
}

// Every inline run step must be in the ratchet. This is the assertion that
// makes adding one a deliberate act.
func TestEveryInlineRunStepIsRatcheted(t *testing.T) {
	wf := loadWorkflow(t)

	var named []string
	for _, job := range []string{"build", "release"} {
		for _, step := range wf.Jobs[job].Steps {
			if strings.TrimSpace(step.Run) == "" {
				continue
			}
			if step.Name == "" {
				t.Errorf("job %q has an inline run step with no name; the ratchet cannot see it", job)
				continue
			}
			named = append(named, step.Name)
		}
	}

	var known []string
	for name := range ceiling {
		known = append(known, name)
	}
	sort.Strings(named)
	sort.Strings(known)

	if len(named) != len(known) {
		t.Errorf("the workflow has %d inline run steps and the ratchet knows %d", len(named), len(known))
	}
	for _, name := range named {
		if _, ok := ceiling[name]; !ok {
			t.Errorf("step %q is not in the ratchet; add it with a line budget", name)
		}
	}
	for _, name := range known {
		if !slices.Contains(named, name) {
			t.Errorf("the ratchet lists %q, which the workflow no longer has", name)
		}
	}
}

func TestNoRunStepExceedsItsBudget(t *testing.T) {
	wf := loadWorkflow(t)
	for _, job := range []string{"build", "release"} {
		for _, step := range wf.Jobs[job].Steps {
			max, ok := ceiling[step.Name]
			if !ok {
				continue
			}
			lines := len(strings.Split(strings.TrimRight(step.Run, "\n"), "\n"))
			if lines > max {
				t.Errorf("step %q is %d lines, budget %d. Shrink it, or raise the budget and say why",
					step.Name, lines, max)
			}
		}
	}
}

// The draft-then-verify-then-publish order is the whole reason a release with a
// broken notes body has never been public. Asserted as shape, because the
// failure it prevents leaves no trace in any generator test.
func TestTheReleaseIsDraftedBeforeItIsVerified(t *testing.T) {
	wf := loadWorkflow(t)
	steps := wf.Jobs["release"].Steps

	draft, verify := -1, -1
	for i, s := range steps {
		if strings.Contains(s.Uses, "action-gh-release") {
			draft = i
		}
		if strings.Contains(s.Name, "Verify the published notes") {
			verify = i
		}
	}
	if draft < 0 {
		t.Fatal("the release job never creates a release")
	}
	if verify < 0 {
		t.Fatal("the release job never verifies the published notes")
	}
	if verify < draft {
		t.Error("the notes are verified before the release is created; nothing would be checked")
	}
}

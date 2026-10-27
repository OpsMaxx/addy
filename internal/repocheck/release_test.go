package repocheck

import (
	"fmt"
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
	// 16: also checks Chart.yaml's appVersion, which the chart pulls by default.
	"Check the tag matches the version the binary reports": 16,
	"Copy the image's binaries out for scanning":           8,
	"Tag the scanned image":                                6,
	"Build every target":                                   3,
	"Check the build is reproducible":                      10,
	"Scan the binaries with ClamAV":                        18,
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

// The image is pushed under the tag the chart and the installer pull, only
// after the tests pass AND the scans pass, and never as `:latest` for a
// prerelease.
//
// It used to be pushed as `:v0.1.0` while the chart pulled `:0.1.0`, in a job
// that did not wait for the tests; then as `:0.1.0` and `:latest` before the
// release job had scanned anything. The VirusTotal step read its key from its
// own `env`, which a step's `if:` cannot see, so it never ran.
func TestTheImageIsTaggedTheWayEverythingPullsIt(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRoot(t), ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var wf struct {
		Jobs map[string]struct {
			Needs any               `yaml:"needs"`
			Env   map[string]string `yaml:"env"`
			Steps []struct {
				Name string            `yaml:"name"`
				Run  string            `yaml:"run"`
				If   string            `yaml:"if"`
				Env  map[string]string `yaml:"env"`
				With map[string]any    `yaml:"with"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(b, &wf); err != nil {
		t.Fatal(err)
	}

	image := wf.Jobs["image"]
	if !strings.Contains(fmt.Sprint(image.Needs), "build") {
		t.Error("the image job does not wait for the build job, which is where the tests run")
	}
	for _, s := range image.Steps {
		if _, ok := s.With["tags"]; ok {
			t.Errorf("the image job pushes named tags (%v) before anything is scanned", s.With["tags"])
		}
		if out, ok := s.With["outputs"]; ok && !strings.Contains(fmt.Sprint(out), "push-by-digest=true") {
			t.Errorf("the image job pushes %v; it should push by digest only", out)
		}
	}

	clam, tag := -1, -1
	var naming string
	for i, s := range wf.Jobs["release"].Steps {
		if strings.Contains(s.Name, "ClamAV") {
			clam = i
		}
		if s.Name == "Tag the scanned image" {
			tag, naming = i, s.Run
		}
	}
	if tag < 0 || clam < 0 || tag < clam {
		t.Errorf("the image is tagged at step %d and scanned at step %d; tagging must come after the scan", tag, clam)
	}
	if !strings.Contains(naming, `${GITHUB_REF_NAME#v}`) {
		t.Error("the image tag keeps the git tag's `v`; the chart and installer pull it without one")
	}
	if !strings.Contains(naming, "*-*") {
		t.Error("`:latest` is not withheld from prereleases")
	}

	release := wf.Jobs["release"]
	for _, s := range release.Steps {
		if strings.Contains(s.If, "env.VT_API_KEY") {
			if _, ok := s.Env["VT_API_KEY"]; ok {
				t.Error("VT_API_KEY is set on the VirusTotal step itself, where its own `if:` cannot see it")
			}
			if _, ok := release.Env["VT_API_KEY"]; !ok {
				t.Error("the VirusTotal step tests env.VT_API_KEY but the release job does not set it")
			}
		}
	}

	// And the chart pulls what is pushed: appVersion has no `v`.
	chart, err := os.ReadFile(filepath.Join(repoRoot(t), "deploy", "helm", "addy", "Chart.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(chart), `appVersion: "v`) {
		t.Error("Chart.yaml's appVersion starts with v; images are pushed without one")
	}
}

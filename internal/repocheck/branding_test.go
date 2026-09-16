package repocheck

import (
	"bytes"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// The retired product name must not appear anywhere in this repository.
//
// addy is a sibling of OpsMaxx, which renamed away from an earlier name and
// enforces the same rule with tests/branding.test.ts. That file's own comment
// explains why the rule is inherited here from day one rather than added later:
// a check bolted on after the fact needs exemptions for everything that already
// violated it, and an allowlist whose one entry is the test doing the checking
// is how a gate like this quietly stops working.
//
// So the needle is ASSEMBLED AT RUNTIME. This file therefore contains no
// occurrence of the string it searches for, needs no self-exemption, and the
// allowlist is empty because there is nothing to exempt.
//
// Why there is also a SECOND repository: never create one at the old name.
// GitHub left a 301 there when OpsMaxx was renamed, and that redirect is what
// keeps every already-published release-asset URL working. A repository at the
// old name replaces the redirect and breaks all of them permanently.
func needle() string {
	return strings.Join([]string{"shell", "pilot"}, "")
}

// gitOut runs a git command at the repository root and returns its stdout.
//
// `git grep` exits 1 to mean "no match", which is the outcome we want, so exit
// 1 is not an error here. Any other non-zero status is a real failure and must
// not be mistaken for a clean result — a broken search that reports success is
// worse than no search.
func gitOut(t *testing.T, wantEmptyOnOne bool, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = repoRoot(t)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok && wantEmptyOnOne && ee.ExitCode() == 1 {
			return ""
		}
		t.Fatalf("git %s failed: %v\n%s", strings.Join(args, " "), err, errb.String())
	}
	return out.String()
}

func repoRoot(t *testing.T) string {
	t.Helper()
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("not a git repository: %v", err)
	}
	return strings.TrimSpace(string(out))
}

// -a makes git grep read committed binary files as text. That is not
// belt-and-braces: the last time this slipped through in the sibling repo, it
// was a Go module path sitting in a compiled binary's strings.
func TestNoRetiredNameInTrackedFiles(t *testing.T) {
	hits := gitOut(t, true, "grep", "-a", "-i", "-n", needle())
	if strings.TrimSpace(hits) != "" {
		t.Errorf("the retired product name appears in tracked files:\n%s", hits)
	}
}

func TestNoRetiredNameInTrackedPaths(t *testing.T) {
	files := strings.Split(gitOut(t, false, "ls-files"), "\n")
	var bad []string
	for _, f := range files {
		if f != "" && strings.Contains(strings.ToLower(f), needle()) {
			bad = append(bad, f)
		}
	}
	if len(bad) > 0 {
		t.Errorf("the retired product name appears in tracked paths:\n%s", strings.Join(bad, "\n"))
	}
}

var markup = regexp.MustCompile(`<[^>]*>`)
var whitespace = regexp.MustCompile(`\s+`)
var searchable = regexp.MustCompile(`\.(go|md|html|css|json|ya?ml|sh|txt)$`)

// A two-tone wordmark split across two elements -- <b>first</b>second -- reads
// as the retired name on screen and matches nothing when searched literally.
// Stripping markup and whitespace before searching is what catches it, and it
// is the bug this assertion was originally written for in the sibling repo.
func TestNoRetiredNameOnceMarkupIsRemoved(t *testing.T) {
	root := repoRoot(t)
	raw := gitOut(t, false, "ls-files", "-z")
	files := strings.Split(strings.TrimRight(raw, "\x00"), "\x00")

	checked := 0
	for _, f := range files {
		if f == "" || !searchable.MatchString(f) {
			continue
		}
		b, err := exec.Command("cat", root+"/"+f).Output()
		if err != nil {
			continue
		}
		checked++
		flat := whitespace.ReplaceAllString(markup.ReplaceAllString(string(b), ""), "")
		if strings.Contains(strings.ToLower(flat), needle()) {
			t.Errorf("%s contains the retired product name once markup is removed", f)
		}
	}

	// A filter that matches nothing would make this test pass vacuously
	// forever. Fail loudly instead: the parser is wrong, not the repository.
	if checked == 0 {
		t.Fatal("checked 0 files; the extension filter is wrong, not the repository")
	}
}

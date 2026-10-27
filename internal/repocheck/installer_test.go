package repocheck

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The installer's own functions, run under bash with curl replaced.
//
// These are the parts of install.sh whose mistakes refuse a box that would
// have worked, or pair an image with the wrong compose file -- and none of
// them can be seen by reading the script, only by running it against an
// answer shaped like the real one.

const fakeCurl = `#!/bin/sh
echo "$@" >> "$CURL_LOG"
out=""
while [ $# -gt 0 ]; do
  case "$1" in -o) out="$2"; shift ;; esac
  shift
done
if [ -n "$out" ]; then echo bundle > "$out"; else printf '%s' "$FAKE_BODY"; fi
`

// runInstaller sources install.sh without its last line (the call to main)
// and runs script against it.
func runInstaller(t *testing.T, env []string, script string) (string, string) {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "curl"), []byte(fakeCurl), 0o755); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(dir, "curl.log")
	installer := filepath.Join(repoRoot(t), "deploy", "compose", "install.sh")

	cmd := exec.Command(bash, "-c", `source <(sed '$d' "$INSTALLER"); `+script)
	cmd.Env = append(os.Environ(),
		"PATH="+bin+":"+os.Getenv("PATH"),
		"ADDY_REEXEC=1", "INSTALLER="+installer, "CURL_LOG="+log,
		"ADDY_INSTALL_DIR="+filepath.Join(dir, "opt"))
	cmd.Env = append(cmd.Env, env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	calls, _ := os.ReadFile(log)
	return string(out), string(calls)
}

// A CNAME'd domain with no AAAA record has no AAAA addresses.
//
// The CNAME target is in the answer as a "data" field too, and used to be
// read as an address -- so every CNAME'd domain appeared to have an AAAA
// record, and an IPv4-only box was refused for not answering on it.
func TestDNSAnswersCountOnlyTheirOwnRecordType(t *testing.T) {
	cname := `{"Status":0,"Question":[{"name":"relay.example.","type":28}],` +
		`"Answer":[{"name":"relay.example.","type":5,"TTL":300,"data":"box.hoster.example."}]}`
	out, _ := runInstaller(t, []string{"FAKE_BODY=" + cname},
		`got="$(doh_resolve relay.example AAAA)"; echo "rc=$? [$got]"`)
	if !strings.Contains(out, "rc=0 []") {
		t.Fatalf("an AAAA lookup that found only a CNAME said %q; it should succeed with no addresses", out)
	}

	both := `{"Status":0,"Answer":[{"name":"relay.example.","type":5,"TTL":300,"data":"box.hoster.example."},` +
		`{"name":"box.hoster.example.","type":1,"TTL":300,"data":"203.0.113.10"}]}`
	out, _ = runInstaller(t, []string{"FAKE_BODY=" + both}, `doh_resolve relay.example A`)
	if strings.TrimSpace(out) != "203.0.113.10" {
		t.Fatalf("an A lookup through a CNAME gave %q; want only the address", out)
	}
}

// The compose bundle comes from the release the image does.
func TestThePinnedVersionGetsItsOwnComposeFile(t *testing.T) {
	_, calls := runInstaller(t, nil, `ADDY_VERSION=0.1.0; fetch_bundle`)
	if !strings.Contains(calls, "/releases/download/v0.1.0/docker-compose.yml") {
		t.Fatalf("a box pinned to 0.1.0 fetched %q", calls)
	}
	_, calls = runInstaller(t, nil, `ADDY_VERSION=latest; fetch_bundle`)
	if !strings.Contains(calls, "/releases/latest/download/docker-compose.yml") {
		t.Fatalf("a box on latest fetched %q", calls)
	}
}

// An upgrade of a box whose .env predates the relay setting gives it one,
// and says what to open -- the fresh-install path did, the upgrade did not.
func TestAnUpgradeAddsTheRelayAddressAnOldEnvLacks(t *testing.T) {
	out, _ := runInstaller(t, []string{"FAKE_BODY=fl=1\nip=203.0.113.7\n"}, `
		mkdir -p "$ADDY_INSTALL_DIR"
		printf 'ADDY_DOMAIN=relay.example\nADDY_VERSION=latest\n' > "$ADDY_INSTALL_DIR/.env"
		check_root() { :; }; check_docker() { :; }; pull_image() { :; }
		fetch_bundle() { :; }; start() { :; }; verify() { :; }
		docker() { echo "addy 0.2.0"; }
		upgrade ""
		echo "--- env"; cat "$ADDY_INSTALL_DIR/.env"`)
	if !strings.Contains(out, "ADDY_TURN_PUBLIC_IP=203.0.113.7") {
		t.Errorf("the upgraded .env has no relay address:\n%s", out)
	}
	if !strings.Contains(out, "TURN relay advertises 203.0.113.7") {
		t.Errorf("the upgrade did not say which ports the relay needs open:\n%s", out)
	}
}

// preflight keeps a throwaway ACME account in /tmp, and the image is FROM
// scratch. Without a /tmp it failed before contacting anything -- and the
// installer reported that as the operator's firewall.
func TestPreflightHasATmpToWriteTo(t *testing.T) {
	root := repoRoot(t)
	docker, err := os.ReadFile(filepath.Join(root, "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	final := string(docker[strings.LastIndex(string(docker), "FROM scratch"):])
	if !strings.Contains(final, " /tmp\n") {
		t.Error("the runtime image has no /tmp")
	}
	install, err := os.ReadFile(filepath.Join(root, "deploy", "compose", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(install), "--tmpfs /tmp") {
		t.Error("the installer runs preflight with no /tmp, which images published before this had none of")
	}
	if strings.Contains(string(install), "An ACME challenge for $domain did not complete") {
		t.Error("the installer still reports every preflight failure as port 80 being unreachable")
	}
}

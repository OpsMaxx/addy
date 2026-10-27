package repocheck

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"

	"github.com/opsmaxx/addy/internal/relay"
)

// ONE TURN relay range, the binary's, everywhere an operator reads one.
//
// The binary allocated from 61000-65535 while the installer opened and advised
// 49160-49360, the compose file set two variables nothing read, the chart
// offered 52000-65535 values it never passed, and a service template reasoned
// about 52000. Every firewall rule written from those was open on ports the
// relay never used.
func TestEveryDeploymentNamesTheBinarysRelayRange(t *testing.T) {
	root := repoRoot(t)
	want := strconv.Itoa(int(relay.DefaultMinPort))

	install, err := os.ReadFile(filepath.Join(root, "deploy", "compose", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^ADDY_RELAY_MIN=(\d+)\s*$`).FindSubmatch(install)
	if m == nil || string(m[1]) != want {
		t.Errorf("install.sh's relay floor is %q; the binary's is %s", m, want)
	}
	m = regexp.MustCompile(`(?m)^ADDY_RELAY_MAX=(\d+)\s*$`).FindSubmatch(install)
	if m == nil || string(m[1]) != strconv.Itoa(int(relay.DefaultMaxPort)) {
		t.Errorf("install.sh's relay ceiling is %q; the binary's is %d", m, relay.DefaultMaxPort)
	}

	// No file offers a range of its own, because nothing would read it.
	for _, rel := range []string{
		"deploy/compose/docker-compose.yml",
		"deploy/compose/install.sh",
		"deploy/helm/addy/values.yaml",
		"deploy/helm/addy/templates/statefulset.yaml",
		"Dockerfile",
	} {
		b, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatal(err)
		}
		for _, stale := range []string{"RELAY_MIN:", "RELAY_MAX:", "TURN_RELAY_MIN", "minPort", "--relay-range", "49160", "52000", "5349"} {
			if regexp.MustCompile(regexp.QuoteMeta(stale)).Match(b) {
				t.Errorf("%s still says %q; the relay range is the binary's and is not configurable", rel, stale)
			}
		}
	}
}

package repocheck

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The Helm chart, checked as far as it can be without Helm.
//
// `helm lint` and `helm template` are the real gate and they run in CI, where
// Helm is installed. These are the checks that do not need it: that the chart
// parses, that its versions do not silently track each other, and that the
// three refusals are actually in the templates. A chart whose guard rails were
// deleted would still lint.

func chartPath(t *testing.T, parts ...string) string {
	t.Helper()
	return filepath.Join(append([]string{"..", "..", "deploy", "helm", "addy"}, parts...)...)
}

func readChartFile(t *testing.T, parts ...string) string {
	t.Helper()
	b, err := os.ReadFile(chartPath(t, parts...))
	if err != nil {
		t.Fatalf("reading %v: %v", parts, err)
	}
	return string(b)
}

func TestTheChartParses(t *testing.T) {
	var chart struct {
		APIVersion string `yaml:"apiVersion"`
		Name       string `yaml:"name"`
		Version    string `yaml:"version"`
		AppVersion string `yaml:"appVersion"`
	}
	if err := yaml.Unmarshal([]byte(readChartFile(t, "Chart.yaml")), &chart); err != nil {
		t.Fatalf("Chart.yaml: %v", err)
	}
	if chart.APIVersion != "v2" || chart.Name != "addy" {
		t.Fatalf("Chart.yaml says apiVersion=%q name=%q", chart.APIVersion, chart.Name)
	}
	// Two versions that are not the same field. The chart version moves when
	// the TEMPLATES change; appVersion tracks the server. Conflating them
	// means a chart fix cannot ship without pretending to be a new release.
	if chart.Version == "" || chart.AppVersion == "" {
		t.Fatal("Chart.yaml needs both version and appVersion")
	}

	var values map[string]any
	if err := yaml.Unmarshal([]byte(readChartFile(t, "values.yaml")), &values); err != nil {
		t.Fatalf("values.yaml: %v", err)
	}
	// Required and deliberately empty: addy refuses to serve a name it was not
	// configured for, and a default here would be a name it answers for by
	// accident.
	if got, ok := values["domain"]; !ok || got != "" {
		t.Fatalf("values.yaml ships domain=%v; it must be empty and required", got)
	}
}

// The three refusals, which fail a release BEFORE anything is applied rather
// than as a CrashLoopBackOff somebody has to read logs to explain.
func TestTheChartRefusesTheThreeThingsItShould(t *testing.T) {
	helpers := readChartFile(t, "templates", "_helpers.tpl")
	for _, want := range []struct{ needle, why string }{
		{"addy needs a domain", "a release with no domain"},
		{"turn.enabled needs turn.publicIP", "a relay that would advertise an address it cannot know"},
		{"51820", "a TURN range that collides with WireGuard"},
	} {
		if !strings.Contains(helpers, want.needle) {
			t.Errorf("the chart no longer refuses %s", want.why)
		}
	}
	// Every template has to invoke the validation, or a release that skips the
	// one template carrying it is a release with no guard rails.
	for _, name := range []string{"statefulset.yaml", "service.yaml"} {
		if !strings.Contains(readChartFile(t, "templates", name), `include "addy.validate"`) {
			t.Errorf("templates/%s does not run the validation", name)
		}
	}
}

// A StatefulSet with one replica, and no ingress.
func TestTheChartDoesNotQuietlyGiveUpTheRouting(t *testing.T) {
	sts := readChartFile(t, "templates", "statefulset.yaml")
	if !strings.Contains(sts, "kind: StatefulSet") {
		t.Error("addy is not a StatefulSet; two replicas sharing one volume corrupt the database, " +
			"and two with separate volumes are two relays with two rosters and one hostname")
	}
	if !strings.Contains(sts, "replicas: 1") {
		t.Error("the chart does not pin one replica")
	}

	// NO INGRESS TEMPLATE, deliberately. addy terminates TLS itself and routes
	// by SNI, which is how four things share 443 on one box. An ingress
	// controller terminates TLS in front of it and addy then sees one hostname
	// for everything -- so the chart does not offer one rather than offering
	// one that breaks the design quietly.
	entries, err := os.ReadDir(chartPath(t, "templates"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(strings.ToLower(e.Name()), "ingress") {
			t.Errorf("templates/%s exists; an ingress terminates TLS in front of a server whose "+
				"whole routing design is that it terminates TLS itself", e.Name())
		}
	}
	if !strings.Contains(readChartFile(t, "values.yaml"), "there is no ingress template") {
		t.Error("values.yaml does not explain why there is no ingress")
	}
}

// The liveness probe has to prove the instance ANSWERS, not that the process
// is up. A relay that is running and cannot serve is the worst first
// impression the product can make, and "the container is running" is exactly
// the evidence that produces it.
func TestTheProbesUseSelftest(t *testing.T) {
	sts := readChartFile(t, "templates", "statefulset.yaml")
	if strings.Count(sts, "selftest") < 2 {
		t.Error("liveness and readiness do not both run `addy selftest -quick`")
	}
	if !strings.Contains(sts, "-quick") {
		t.Error("the probes run a full selftest; -quick is what a 30-second probe should run")
	}
}

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

// The refusals, which fail a release BEFORE anything is applied rather than as
// a CrashLoopBackOff somebody has to read logs to explain.
//
// There were three. The third refused a TURN range containing 51820 -- for
// minPort/maxPort values the chart never passed to addy, which allocates from
// its own fixed range. A guard on a setting that does nothing is not a guard.
func TestTheChartRefusesTheThingsItShould(t *testing.T) {
	helpers := readChartFile(t, "templates", "_helpers.tpl")
	for _, want := range []struct{ needle, why string }{
		{"addy needs a domain", "a release with no domain"},
		{"turn.enabled needs turn.publicIP", "a relay that would advertise an address it cannot know"},
		{"turn.enabled needs turn.hostNetwork", "a relay whose range no Service carries"},
		{"oidc needs issuer, clientID and clientSecretName together", "half a sign-in config, which addy refuses at startup"},
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

// Readiness has to prove the instance ANSWERS FOR ITS DOMAIN, not that the
// process is up -- and it has to be able to pass.
//
// Both probes used to run `selftest -quick -target localhost:443`. The front
// door drops every name it has no route for, localhost included outside dev,
// so the pod was never Ready and the liveness probe restarted it for ever.
func TestTheProbesCanPass(t *testing.T) {
	sts := readChartFile(t, "templates", "statefulset.yaml")
	var probes struct {
		Spec struct {
			Template struct {
				Spec struct {
					Containers []struct {
						Liveness map[string]any `yaml:"livenessProbe"`
						Startup  struct {
							PeriodSeconds    int `yaml:"periodSeconds"`
							FailureThreshold int `yaml:"failureThreshold"`
						} `yaml:"startupProbe"`
						Readiness struct {
							Exec struct {
								Command []string `yaml:"command"`
							} `yaml:"exec"`
						} `yaml:"readinessProbe"`
					} `yaml:"containers"`
				} `yaml:"spec"`
			} `yaml:"template"`
		} `yaml:"spec"`
	}
	// The template directives are not YAML; drop those lines, keep the rest.
	var plain []string
	for _, line := range strings.Split(sts, "\n") {
		if !strings.Contains(line, "{{") {
			plain = append(plain, line)
		}
	}
	if err := yaml.Unmarshal([]byte(strings.Join(plain, "\n")), &probes); err != nil {
		t.Fatalf("statefulset.yaml without its directives: %v", err)
	}
	c := probes.Spec.Template.Spec.Containers[0]

	cmd := strings.Join(c.Readiness.Exec.Command, " ")
	if !strings.Contains(cmd, "selftest -quick") {
		t.Errorf("readiness runs %q; it should run `addy selftest -quick`", cmd)
	}
	if strings.Contains(cmd, "localhost") || !strings.Contains(cmd, "-connect 127.0.0.1:443") {
		t.Errorf("readiness runs %q; it must dial loopback and name the domain, which the front door answers for", cmd)
	}
	// Liveness must not depend on a certificate existing, or a slow first
	// issuance restarts the pod mid-order.
	if _, ok := c.Liveness["tcpSocket"]; !ok {
		t.Errorf("liveness is %v; anything that needs TLS restarts the pod before its certificate is issued", c.Liveness)
	}
	// Nothing listens while a pre-upgrade database copy runs, and liveness
	// used to kill the pod mid-copy. Ten minutes at least before it may.
	if c.Startup.PeriodSeconds*c.Startup.FailureThreshold < 600 {
		t.Errorf("the startup probe allows %ds; a multi-GB database copy needs minutes",
			c.Startup.PeriodSeconds*c.Startup.FailureThreshold)
	}
	// preflight binds :80, which the running pod already holds, so telling
	// an operator to run it there sends them to a failure every time.
	if strings.Contains(readChartFile(t, "templates", "NOTES.txt"), "-- /addy preflight") {
		t.Error("NOTES.txt runs preflight inside the running pod, where port 80 is addy's")
	}
	// And Not Ready must still receive the ACME challenge.
	if !strings.Contains(readChartFile(t, "templates", "service.yaml"), "publishNotReadyAddresses: true") {
		t.Error("the Service drops Not-Ready pods, so the challenge that would make the pod Ready never arrives")
	}
	// The probes find the domain in the environment.
	if !strings.Contains(sts, "name: ADDY_DOMAIN") {
		t.Error("ADDY_DOMAIN is not in the pod's environment, so the probe has no name to send")
	}
}

package services_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opsmaxx/addy/internal/services"
)

// Every wizard declares what it costs.
//
// Not a style rule. addy's pitch is a box that holds nothing worth attacking,
// and every service here weakens that; a service with nothing to declare has
// not been thought about, and the operator finds out what it cost afterwards.
func TestEveryServiceStatesItsCost(t *testing.T) {
	all := services.All()
	if len(all) != 5 {
		t.Fatalf("there are %d wizards; the plan calls for five", len(all))
	}
	for _, s := range all {
		if strings.TrimSpace(s.Cost) == "" {
			t.Errorf("%s declares no cost", s.ID)
		}
		if strings.TrimSpace(s.Summary) == "" {
			t.Errorf("%s has no summary", s.ID)
		}
		if s.Template == "" {
			t.Errorf("%s names no template", s.ID)
		}
	}
}

// The cost is in the LIST, not only in the detail view. The list is where
// somebody decides what to look at, and a cost discovered after deciding is
// discovered too late to affect the decision.
func TestTheListPrintsTheCost(t *testing.T) {
	var out bytes.Buffer
	services.List(&out)
	text := out.String()
	for _, s := range services.All() {
		if !strings.Contains(text, s.ID) {
			t.Errorf("the list omits %s", s.ID)
		}
	}
	// Vaultwarden's is the sharpest and the one most worth not burying.
	if !strings.Contains(text, "password database") {
		t.Error("the list does not say what Vaultwarden costs")
	}
}

// THE PREREQUISITE THAT CANNOT BE WORKED AROUND.
//
// Let's Encrypt will not issue a wildcard over HTTP-01. Not "does not by
// default" -- will not, by design, because the challenge proves control of one
// name and a wildcard claims all of them. A deployment that assumed otherwise
// works perfectly until the certificate is requested, and then fails in a way
// that looks like a DNS problem.
func TestAWildcardNeedsADnsCredential(t *testing.T) {
	frp, err := services.Find("frp")
	if err != nil {
		t.Fatal(err)
	}

	wildcardNoToken := services.Config{Values: map[string]string{
		"FRP_TOKEN":    "a-token",
		"FRP_WILDCARD": "true",
	}}
	if !failed(services.Check(frp, wildcardNoToken), "DNS credential") {
		t.Fatal("a wildcard with no DNS credential was accepted")
	}

	withToken := services.Config{Values: map[string]string{
		"FRP_TOKEN":        "a-token",
		"FRP_WILDCARD":     "true",
		"FRP_DNS_PROVIDER": "cloudflare",
		"FRP_DNS_TOKEN":    "secret",
	}}
	if failed(services.Check(frp, withToken), "DNS credential") {
		t.Fatal("a wildcard with a DNS credential was still refused")
	}

	// And the fallback the wizard offers instead: name the subdomains.
	named := services.Config{Values: map[string]string{
		"FRP_TOKEN":      "a-token",
		"FRP_SUBDOMAINS": "build,metrics",
	}}
	if failed(services.Check(frp, named), "DNS credential") {
		t.Fatal("named subdomains without a wildcard were refused")
	}

	// Neither: the operator has to choose, and is told what each choice costs.
	neither := services.Config{Values: map[string]string{"FRP_TOKEN": "a-token"}}
	if !failed(services.Check(frp, neither), "DNS credential") {
		t.Fatal("frp with neither a wildcard nor named subdomains was accepted")
	}
}

func TestATokenlessFrpIsRefused(t *testing.T) {
	frp, _ := services.Find("frp")
	// frp with no token accepts a tunnel from anyone who finds the port, which
	// makes the box an open proxy.
	if !failed(services.Check(frp, services.Config{Values: map[string]string{}}), "token") {
		t.Fatal("frp with no token was accepted")
	}
}

// Every prerequisite runs, not just up to the first failure.
//
// A preflight that stops at the first problem turns a ten-minute job into four
// rounds of run-fix-run, and the fourth round is where people disable the
// checks.
func TestEveryCheckRunsEvenAfterOneFails(t *testing.T) {
	frp, _ := services.Find("frp")
	results := services.Check(frp, services.Config{Values: map[string]string{}})

	var names []string
	for _, r := range results {
		names = append(names, r.Name)
	}
	if len(results) < 3 {
		t.Fatalf("only %d checks ran: %v", len(results), names)
	}
	var fails int
	for _, r := range results {
		if !r.OK && r.Fatal {
			fails++
		}
	}
	// The missing token AND the missing wildcard decision, in one pass.
	if fails < 2 {
		t.Fatalf("only %d fatal failures reported; the operator gets one round of fixes: %v", fails, names)
	}
}

// NOTHING IS WRITTEN WHEN A FATAL CHECK FAILS.
//
// A wizard that writes half a deployment and then discovers the port is taken
// leaves an operator with a broken box and a half-finished config they did not
// author and cannot read.
func TestNothingIsWrittenWhenAPrerequisiteFails(t *testing.T) {
	dir := t.TempDir()
	frp, _ := services.Find("frp")

	_, err := services.Render(frp, services.Config{
		Values:    map[string]string{}, // no token
		DeployDir: dir,
	})
	if err == nil {
		t.Fatal("Render succeeded with a failing prerequisite")
	}
	entries, _ := os.ReadDir(filepath.Join(dir, "services"))
	if len(entries) != 0 {
		t.Fatalf("%d file(s) were written anyway", len(entries))
	}
}

func TestRenderSubstitutesTheAnswers(t *testing.T) {
	vw, _ := services.Find("vaultwarden")

	text, err := services.Preview(vw, services.Config{
		Values: map[string]string{"VW_SIGNUPS": "false", "VW_ADMIN_TOKEN": ""},
		Domain: "relay.example",
	})
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if !strings.Contains(text, "https://relay.example") {
		t.Errorf("the domain was not substituted:\n%s", text)
	}
	// No placeholder may survive into a file an operator is about to run.
	if strings.Contains(text, "${") {
		for _, line := range strings.Split(text, "\n") {
			if strings.Contains(line, "${") {
				t.Errorf("an unsubstituted placeholder reached the output: %s", line)
			}
		}
	}
}

// Vaultwarden, headscale and frp all terminate behind addy's front door.
// Publishing their ports directly is the four-way collision on 443 that the
// front door exists to prevent.
func TestTheProxiedServicesStayOnLoopback(t *testing.T) {
	// Preview rather than Render: this is a question about the templates, and
	// a test that also asked whether port 8080 is free on the machine running
	// it would be a test that fails on whoever happens to have something
	// listening.
	for _, id := range []string{"vaultwarden", "headscale"} {
		s, err := services.Find(id)
		if err != nil {
			t.Fatal(err)
		}
		body, err := services.Preview(s, services.Config{
			Values: map[string]string{"HEADSCALE_PREFIX": "100.64.0.0/10", "HEADSCALE_DERP": "false"},
			Domain: "relay.example",
		})
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		for _, line := range strings.Split(body, "\n") {
			trimmed := strings.TrimSpace(line)
			if !strings.HasPrefix(trimmed, "- \"") || !strings.Contains(trimmed, ":") {
				continue
			}
			if strings.Contains(trimmed, "127.0.0.1:") || strings.Contains(trimmed, "#") {
				continue
			}
			t.Errorf("%s publishes %s on every interface; it belongs behind the front door", id, trimmed)
		}
	}
}

// headscale's DERP is off, and the template says why: turning it on binds
// 3478/udp, which is addy's own TURN port.
func TestHeadscaleDerpIsOffAndSaysWhy(t *testing.T) {
	hs, _ := services.Find("headscale")
	var derp services.Field
	for _, f := range hs.Fields {
		if f.Key == "HEADSCALE_DERP" {
			derp = f
		}
	}
	if derp.Key == "" {
		t.Fatal("headscale has no DERP field")
	}
	if derp.Default != "false" {
		t.Errorf("DERP defaults to %q", derp.Default)
	}
	if !strings.Contains(derp.Help, "OFF by default") {
		t.Errorf("the DERP field does not say it is off: %q", derp.Help)
	}
}

// The socket proxy is written once, and its own comment says what it is not.
func TestTheSocketProxyDoesNotOverclaim(t *testing.T) {
	// A socket proxy described as "hardening" is one people trust to hold
	// weight it cannot hold: POST /containers/create is granted, because
	// installing a service needs it, and that call alone is enough to mount
	// the host filesystem.
	if !strings.Contains(services.SocketProxyCompose, "not a boundary against code already running here") {
		t.Error("the socket proxy template does not state its limit")
	}
	for _, off := range []string{`EXEC: "0"`, `SWARM: "0"`, `PLUGINS: "0"`} {
		if !strings.Contains(services.SocketProxyCompose, off) {
			t.Errorf("the socket proxy does not explicitly set %s", off)
		}
	}
}

func failed(results []services.CheckResult, substring string) bool {
	for _, r := range results {
		if !r.OK && r.Fatal && strings.Contains(r.Name+" "+r.Why, substring) {
			return true
		}
	}
	return false
}

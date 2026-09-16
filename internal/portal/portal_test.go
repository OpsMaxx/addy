package portal

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func newServer(t *testing.T) http.Handler {
	t.Helper()
	h, err := Handler(Config{Version: "1.2.3", BuildSha: "abc1234"})
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}
	return NoServiceWorker(h)
}

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestIndexIsServedWithItsSecurityHeaders(t *testing.T) {
	rec := get(t, newServer(t), "/")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", rec.Code)
	}
	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
		"X-Robots-Tag":           "noindex, nofollow, noarchive, nosnippet",
	}
	for k, v := range want {
		if got := rec.Header().Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
}

// The CSP is the paste's real defence: it cannot stop a page reading its own
// fragment, but it can make sure no injected script is ever the one running.
// 'unsafe-inline' or 'unsafe-eval' anywhere gives that away completely.
func TestCSPAllowsNoInlineOrEvaluatedScript(t *testing.T) {
	policy := get(t, newServer(t), "/").Header().Get("Content-Security-Policy")
	if policy == "" {
		t.Fatal("no Content-Security-Policy header")
	}
	for _, forbidden := range []string{"unsafe-inline", "unsafe-eval", "*"} {
		if strings.Contains(policy, forbidden) {
			t.Errorf("CSP contains %q: %s", forbidden, policy)
		}
	}
	for _, required := range []string{"default-src 'none'", "script-src 'self'", "frame-ancestors 'none'"} {
		if !strings.Contains(policy, required) {
			t.Errorf("CSP is missing %q: %s", required, policy)
		}
	}
}

// RE2 has no negative lookahead, so empty <script src=...></script> pairs are
// removed first and anything still calling itself a script must have a body.
var emptyScriptPair = regexp.MustCompile(`(?is)<script(?:\s[^>]*)?>\s*</script>`)
var anyScript = regexp.MustCompile(`(?i)<script`)
var inlineStyleAttr = regexp.MustCompile(`(?i)\sstyle\s*=`)
var inlineHandler = regexp.MustCompile(`(?i)\son[a-z]+\s*=`)

// A CSP without 'unsafe-inline' and a page that needs inline script are a
// contradiction, and the way that contradiction gets resolved in practice is
// by weakening the CSP. So the markup is asserted directly: if this fails, fix
// the markup, not the policy.
func TestTheMarkupDoesNotNeedAWeakerPolicy(t *testing.T) {
	index := readAsset(t, "index.html")
	if anyScript.MatchString(emptyScriptPair.ReplaceAllString(index, "")) {
		t.Error("index.html contains an inline <script> body; the CSP forbids it")
	}
	if inlineStyleAttr.MatchString(index) {
		t.Error("index.html contains a style= attribute; the CSP forbids it")
	}
	if inlineHandler.MatchString(index) {
		t.Error("index.html contains an inline event handler; the CSP forbids it")
	}
}

// The fragment carries a paste's decryption key. Nothing the portal ships may
// read it -- not to be clever, not to be helpful, not once.
func TestNoShippedScriptReadsTheURLFragment(t *testing.T) {
	sub, err := fs.Sub(assets, "web")
	if err != nil {
		t.Fatalf("fs.Sub: %v", err)
	}
	checked := 0
	err = fs.WalkDir(sub, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".js") {
			return err
		}
		b, err := fs.ReadFile(sub, path)
		if err != nil {
			return err
		}
		checked++
		body := string(b)
		// Skip the comment that explains the rule.
		for _, needle := range []string{"location.hash", "window.location.hash", ".hash"} {
			for _, line := range strings.Split(body, "\n") {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
					continue
				}
				if strings.Contains(line, needle) {
					t.Errorf("%s reads the URL fragment: %s", path, trimmed)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if checked == 0 {
		t.Fatal("checked 0 scripts; the filter is wrong, not the code")
	}
}

// Nothing to unfurl means nothing prefetches a paste into oblivion.
func TestThePageCarriesNoOpenGraphTags(t *testing.T) {
	index := strings.ToLower(readAsset(t, "index.html"))
	for _, needle := range []string{`property="og:`, `name="twitter:`, `property='og:`} {
		if strings.Contains(index, needle) {
			t.Errorf("index.html carries %s; a link preview would fetch the paste", needle)
		}
	}
	if !strings.Contains(index, `name="robots"`) {
		t.Error("index.html is missing its robots meta tag")
	}
}

func TestRobotsDisallowsEverything(t *testing.T) {
	rec := get(t, newServer(t), "/robots.txt")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /robots.txt = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Disallow: /") {
		t.Errorf("robots.txt does not disallow everything: %q", rec.Body.String())
	}
}

// A service worker survives `addy panic` and `addy reset --hard`, because it
// lives in the browser. It would outlive the remediation meant to remove it.
func TestAServiceWorkerRegistrationIsRefused(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/assets/portal.js", nil)
	req.Header.Set("Service-Worker", "script")
	rec := httptest.NewRecorder()
	newServer(t).ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("a service worker fetch returned %d, want 404", rec.Code)
	}

	// And the same path without that header must still work, or the check has
	// broken the portal instead of protecting it.
	if plain := get(t, newServer(t), "/assets/portal.js"); plain.Code != http.StatusOK {
		t.Errorf("GET /assets/portal.js = %d, want 200", plain.Code)
	}
}

// Default-deny applied to an unauthenticated endpoint: it says what build this
// is and nothing else. A field added here without thinking is metadata handed
// to anyone who can reach the port.
func TestMetaExposesTheBuildAndNothingElse(t *testing.T) {
	rec := get(t, newServer(t), "/v1/meta")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/meta = %d, want 200", rec.Code)
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	allowed := map[string]bool{"version": true, "build": true}
	for k := range got {
		if !allowed[k] {
			t.Errorf("/v1/meta exposes %q to unauthenticated callers", k)
		}
	}
	if got["version"] != "1.2.3" || got["build"] != "abc1234" {
		t.Errorf("/v1/meta = %v, want the configured version and build", got)
	}
}

// The page's own job, stated as a test so a redesign cannot quietly drop it.
func TestThePageWarnsAgainstTypingTheRecoveryPhrase(t *testing.T) {
	index := strings.ToLower(readAsset(t, "index.html"))
	if !strings.Contains(index, "recovery phrase") {
		t.Fatal("the portal does not mention the recovery phrase at all")
	}
	if strings.Contains(index, "<input") || strings.Contains(index, "<form") {
		t.Error("the portal has an input or form; it must never have a field a phrase could be typed into")
	}
}

func readAsset(t *testing.T, name string) string {
	t.Helper()
	b, err := fs.ReadFile(assets, "web/"+name)
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return string(b)
}

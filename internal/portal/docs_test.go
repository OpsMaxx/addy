package portal

import (
	"io/fs"
	"net/http"
	"regexp"
	"strings"
	"testing"

	addy "github.com/opsmaxx/addy"
)

// Every document the set names is embedded. A rename in docs/ without the
// matching edit here would otherwise surface as a relay that fails to start.
func TestEveryDocumentInTheSetIsEmbedded(t *testing.T) {
	for _, d := range docSet {
		if _, err := fs.Stat(addy.Docs, d.Path); err != nil {
			t.Errorf("%s (%s): %v", d.Slug, d.Path, err)
		}
	}
}

func TestTheDocsIndexListsEveryPage(t *testing.T) {
	rec := get(t, newServer(t), "/docs")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /docs = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, d := range docSet {
		if !strings.Contains(body, `href="/docs/`+d.Slug+`"`) {
			t.Errorf("index has no link to %s", d.Slug)
		}
	}
	if !strings.Contains(body, "addy 1.2.3") {
		t.Error("index does not show the relay's version")
	}
}

// Rendered pages are not under web/, so the markup rules that walk web/ never
// see them. They are checked here instead, page by page, with the same rules.
func TestEveryDocsPageRendersUnderTheSamePolicy(t *testing.T) {
	h := newServer(t)
	for _, d := range docSet {
		rec := get(t, h, "/docs/"+d.Slug)
		if rec.Code != http.StatusOK {
			t.Errorf("GET /docs/%s = %d", d.Slug, rec.Code)
			continue
		}
		if rec.Header().Get("Content-Security-Policy") == "" {
			t.Errorf("/docs/%s has no CSP", d.Slug)
		}
		page := rec.Body.String()
		if !strings.Contains(page, "<h1") {
			t.Errorf("/docs/%s has no heading", d.Slug)
		}
		if anyScript.MatchString(page) {
			t.Errorf("/docs/%s contains a <script>", d.Slug)
		}
		if inlineStyleAttr.MatchString(page) {
			t.Errorf("/docs/%s contains a style= attribute; the CSP forbids it", d.Slug)
		}
		if inlineHandler.MatchString(page) {
			t.Errorf("/docs/%s contains an inline event handler", d.Slug)
		}
		if !strings.Contains(page, `aria-current="page"`) {
			t.Errorf("/docs/%s does not mark itself in the nav", d.Slug)
		}
	}
}

func TestAnUnknownDocIsNotFound(t *testing.T) {
	h := newServer(t)
	for _, path := range []string{"/docs/nope", "/docs/../go.mod", "/docs/admin/x"} {
		if rec := get(t, h, path); rec.Code == http.StatusOK {
			t.Errorf("GET %s = 200, want an error", path)
		}
	}
}

// A console-only relay serves no front page, and so no docs either.
func TestAConsoleOnlyRelayServesNoDocs(t *testing.T) {
	h, err := Handler(Config{Version: "1.2.3", ConsoleOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if rec := get(t, h, "/docs"); rec.Code == http.StatusOK {
		t.Errorf("GET /docs on a console-only relay = 200")
	}
}

func TestLinksWrittenForTheRepositoryPointSomewhereReal(t *testing.T) {
	cases := []struct{ from, dest, want string }{
		{"README.md", "docs/ADMIN.md", "/docs/admin"},
		{"README.md", "THREAT_MODEL.md#what-the-relay-sees", "/docs/threat-model#what-the-relay-sees"},
		{"docs/ADMIN.md", "../README.md#install", "/docs/overview#install"},
		{"docs/ADMIN.md", "PROTOCOL.md", "/docs/protocol"},
		{"README.md", "deploy/compose/install.sh", sourceBase + "deploy/compose/install.sh"},
		{"docs/ADMIN.md", "decisions/0001.md", sourceBase + "docs/decisions/0001.md"},
		{"README.md", "#install", "#install"},
		{"README.md", "https://example.com/x", "https://example.com/x"},
		{"README.md", "/console", "/console"},
	}
	for _, c := range cases {
		if got := rewriteLink(c.from, c.dest); got != c.want {
			t.Errorf("rewriteLink(%q, %q) = %q, want %q", c.from, c.dest, got, c.want)
		}
	}
}

var rawTag = regexp.MustCompile(`(?i)<(script|iframe|img src="x")`)

// The documents are ours, but nothing here may need a weaker policy: raw HTML
// in Markdown is dropped, never passed through.
func TestRawHTMLInMarkdownIsDropped(t *testing.T) {
	out, err := renderDoc([]byte("hi <script>alert(1)</script>\n\n<iframe src=x></iframe>\n\n[x](javascript:alert(1))\n"), "README.md")
	if err != nil {
		t.Fatal(err)
	}
	if rawTag.MatchString(string(out)) || strings.Contains(string(out), "javascript:") {
		t.Errorf("raw HTML or a script URL survived rendering:\n%s", out)
	}
}

func TestTheFrontPageLinksToTheDocs(t *testing.T) {
	if !strings.Contains(get(t, newServer(t), "/").Body.String(), `href="/docs"`) {
		t.Error("front page has no link to /docs")
	}
}

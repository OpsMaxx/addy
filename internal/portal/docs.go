package portal

import (
	"bytes"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"

	addy "github.com/opsmaxx/addy"
)

// doc is one page under /docs.
type doc struct {
	Slug, Title, Path, Summary string
}

// docSet is what /docs serves, in reading order. Each Path is a file embedded
// by the root package; a test fails the build if one is missing.
var docSet = []doc{
	{"overview", "Overview", "README.md", "What addy is, how to install a relay, and what it is for."},
	{"admin", "Running a relay", "docs/ADMIN.md", "What an operator can and cannot do: the first device, upgrades, backups and rollback."},
	{"operator-signin", "Operator sign-in", "docs/OPERATOR-SIGNIN.md", "Turning on the web console with an OpenID Connect provider."},
	{"threat-model", "Threat model", "THREAT_MODEL.md", "What someone who owns the relay learns, and what they cannot do."},
	{"protocol", "Protocol", "docs/PROTOCOL.md", "Wire formats, signatures and endpoints, for anyone writing a client."},
	{"design", "Design", "docs/DESIGN.md", "The design of record, including the corrections review forced on it."},
}

// sourceBase is where a relative link to anything that is not one of these
// pages goes: the file in the public repository.
const sourceBase = "https://github.com/OpsMaxx/addy/blob/main/"

// rewriteLink maps a link written for the repository onto this site. A link to
// another document in the set stays here; any other relative link goes to the
// file on GitHub, because this relay serves no source tree.
func rewriteLink(from, dest string) string {
	// Anything with a scheme is left exactly as written, so goldmark's own
	// filter still sees a javascript: or data: link and drops it.
	if u, err := url.Parse(dest); err != nil || u.Scheme != "" || u.Host != "" ||
		dest == "" || strings.HasPrefix(dest, "#") || strings.HasPrefix(dest, "/") {
		return dest
	}
	target, frag, hasFrag := strings.Cut(dest, "#")
	clean := path.Clean(path.Join(path.Dir(from), target))
	if strings.HasPrefix(clean, "..") {
		return dest
	}
	suffix := ""
	if hasFrag {
		suffix = "#" + frag
	}
	for _, d := range docSet {
		if d.Path == clean {
			return "/docs/" + d.Slug + suffix
		}
	}
	return sourceBase + clean + suffix
}

type linkRewriter struct{ from string }

func (l linkRewriter) Transform(n *ast.Document, _ text.Reader, _ parser.Context) {
	_ = ast.Walk(n, func(node ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		switch x := node.(type) {
		case *ast.Link:
			x.Destination = []byte(rewriteLink(l.from, string(x.Destination)))
		case *ast.Image:
			x.Destination = []byte(rewriteLink(l.from, string(x.Destination)))
		}
		return ast.WalkContinue, nil
	})
}

// renderDoc turns one document into HTML.
//
// RAW HTML IS DROPPED, not passed through: goldmark omits it unless told it is
// safe, and it is not told. These files are ours, but the portal's rule is that
// nothing it serves may need a weaker policy, and table alignment is emitted as
// an attribute rather than a style for the same reason (the CSP has no
// 'unsafe-inline').
func renderDoc(src []byte, from string) (template.HTML, error) {
	md := goldmark.New(
		goldmark.WithExtensions(extension.NewTable(extension.WithTableCellAlignMethod(extension.TableCellAlignAttribute)),
			extension.Strikethrough, extension.Linkify, extension.TaskList),
		goldmark.WithParserOptions(
			parser.WithAutoHeadingID(),
			parser.WithASTTransformers(util.Prioritized(linkRewriter{from: from}, 100)),
		),
	)
	var buf bytes.Buffer
	if err := md.Convert(src, &buf); err != nil {
		return "", err
	}
	return template.HTML(buf.String()), nil //nolint:gosec // our own files, raw HTML omitted
}

type docsPage struct {
	Title, Slug, Version, Source string
	Index                        bool
	Nav                          []doc
	Body                         template.HTML
}

var docsTemplate = template.Must(template.New("docs").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex, nofollow, noarchive, nosnippet">
<title>{{.Title}} · addy docs</title>
<link rel="stylesheet" href="/assets/portal.css">
<link rel="stylesheet" href="/assets/docs.css">
</head>
<body>
<header class="topbar">
  <a class="brand docs-home" href="/"><span class="brand-mark">a</span><span class="brand-word">addy</span></a>
  <nav aria-label="Site">
    <a class="button ghost small" href="/docs">Docs</a>
    <a class="button ghost small" href="/console">Your console</a>
  </nav>
</header>
<div class="docs">
  <nav class="docs-nav" aria-label="Documentation">
    <ul>
      {{- range .Nav}}
      <li><a href="/docs/{{.Slug}}"{{if eq .Slug $.Slug}} aria-current="page"{{end}}>{{.Title}}</a></li>
      {{- end}}
    </ul>
  </nav>
  <main class="docs-body">
    {{- if .Index}}
    <h1>addy documentation</h1>
    <p class="docs-lede">How to run a relay, what it can and cannot see, and how its protocol works. The same documents are in the <a href="https://github.com/OpsMaxx/addy">addy repository</a>.</p>
    <ul class="docs-index">
      {{- range .Nav}}
      <li><a href="/docs/{{.Slug}}"><strong>{{.Title}}</strong><span>{{.Summary}}</span></a></li>
      {{- end}}
    </ul>
    {{- else}}
    <article class="docs-article">{{.Body}}</article>
    <p class="docs-source"><a href="{{.Source}}">This page on GitHub</a></p>
    {{- end}}
  </main>
</div>
<footer class="docs-foot">addy {{.Version}}</footer>
</body>
</html>
`))

// docsHandler serves /docs and /docs/{slug}, every page rendered once here.
func docsHandler(version string) (http.Handler, error) {
	pages := map[string][]byte{}
	render := func(p docsPage) ([]byte, error) {
		var buf bytes.Buffer
		err := docsTemplate.Execute(&buf, p)
		return buf.Bytes(), err
	}
	index, err := render(docsPage{Title: "Documentation", Version: version, Index: true, Nav: docSet})
	if err != nil {
		return nil, err
	}
	for _, d := range docSet {
		src, err := fs.ReadFile(addy.Docs, d.Path)
		if err != nil {
			return nil, fmt.Errorf("portal: docs: %w", err)
		}
		body, err := renderDoc(src, d.Path)
		if err != nil {
			return nil, fmt.Errorf("portal: rendering %s: %w", d.Path, err)
		}
		page, err := render(docsPage{
			Title: d.Title, Slug: d.Slug, Version: version, Source: sourceBase + d.Path, Nav: docSet, Body: body,
		})
		if err != nil {
			return nil, err
		}
		pages[d.Slug] = page
	}

	serve := func(w http.ResponseWriter, body []byte) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// Public documents, unlike every other page here: nothing in them is
		// about the person reading, so a short cache is fine.
		w.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = w.Write(body)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /docs", func(w http.ResponseWriter, r *http.Request) { serve(w, index) })
	mux.HandleFunc("GET /docs/{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/docs", http.StatusMovedPermanently)
	})
	mux.HandleFunc("GET /docs/{slug}", func(w http.ResponseWriter, r *http.Request) {
		body, ok := pages[r.PathValue("slug")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		serve(w, body)
	})
	return mux, nil
}

// Package portal serves addy's web UI.
//
// THE PORTAL IS ATTACKER SOFTWARE. That is not a worst case, it is the design's
// stated assumption: a compromised addy serves this, and it is same-origin with
// the one-time paste and the public profile. Everything in this package is
// written on the basis that the page cannot be trusted by the person reading
// it, which is why it never asks for a recovery phrase, never reports a value
// whose whole purpose is to be compared out of band, and ships no code that
// touches a key.
package portal

import (
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed web
var assets embed.FS

// Config is what the portal needs to know about the instance around it.
type Config struct {
	Version  string
	BuildSha string
}

// Handler returns the portal's routes.
func Handler(cfg Config) (http.Handler, error) {
	sub, err := fs.Sub(assets, "web")
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	files := http.FileServerFS(sub)

	mux.Handle("GET /assets/", http.StripPrefix("/assets/", files))
	mux.Handle("GET /robots.txt", files)

	// Deliberately the only structured thing the portal serves without
	// authentication, and deliberately boring: a version string and a build
	// hash. Anything that identified the instance, counted its devices or named
	// its users would be handing an unauthenticated caller the metadata the
	// threat model spends its length promising to minimise.
	mux.HandleFunc("GET /v1/meta", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"version": cfg.Version,
			"build":   cfg.BuildSha,
		})
	})

	// The paste reader. One page for every paste: the id is in the path and
	// the KEY is in the fragment, which never reaches this handler -- so this
	// serves the same bytes to everyone and learns nothing by doing it.
	//
	// It does NOT look the paste up. Rendering "already read" server-side
	// would mean this GET touching the row, and a GET that touches the row is
	// one step from a GET that consumes it. The page asks, over the API, after
	// it loads.
	mux.HandleFunc("GET /p/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		page, err := fs.ReadFile(sub, "paste.html")
		if err != nil {
			http.Error(w, "portal unavailable", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(page)
	})

	// The operator console's PAGE. Its routes live in internal/operator and
	// are mounted on the API's mux; this serves the HTML, so the page exists
	// whether or not a provider is configured — and says which of the two it
	// is, rather than 404ing at somebody who typed the address they were told
	// to use.
	mux.HandleFunc("GET /admin", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		page, err := fs.ReadFile(sub, "admin.html")
		if err != nil {
			http.Error(w, "portal unavailable", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(page)
	})

	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		index, err := fs.ReadFile(sub, "index.html")
		if err != nil {
			http.Error(w, "portal unavailable", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(index)
	})

	return headers(mux), nil
}

// The Content-Security-Policy is the paste's real defence, and it is worth
// being precise about why, because the obvious description of it is wrong.
//
// A one-time paste puts its decryption key in the URL fragment, which browsers
// never transmit -- so the server never sees it. But the paste page is
// same-origin with everything else the portal serves, and ANY script running on
// this origin can read location.hash. A CSP cannot stop the page from reading
// its own fragment; what it can do is make sure no script the attacker injected
// is ever the one running. That is the actual control:
//
//	default-src 'none'  -- nothing loads unless named below
//	script-src 'self'   -- no inline script, no eval, no CDN
//
// No 'unsafe-inline' anywhere, which is why portal.js is a file rather than a
// <script> block, and why there is no inline style attribute in index.html.
//
// frame-ancestors 'none' because a framed portal is a clickjacking surface for
// whatever administrative actions the portal grows later.
const csp = "default-src 'none'; " +
	"script-src 'self'; " +
	"style-src 'self'; " +
	"img-src 'self' data:; " +
	"connect-src 'self'; " +
	"form-action 'none'; " +
	"base-uri 'none'; " +
	"frame-ancestors 'none'"

func headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")

		// Every one-time paste service dies the same way: the link is posted
		// in a chat app, the app prefetches it to build a preview, the paste
		// burns, and the human gets an empty page. This header plus
		// robots.txt plus having no OpenGraph tags at all is the part of the
		// answer that is free; the part that actually works is that burning
		// requires an explicit POST, so a prefetch cannot consume anything.
		h.Set("X-Robots-Tag", "noindex, nofollow, noarchive, nosnippet")

		// A service worker would survive both `addy panic` and
		// `addy reset --hard`: it lives in the browser, outliving the
		// remediation that was supposed to remove it, still serving whatever
		// a compromised instance installed. So the portal ships none, and
		// says so at the boundary rather than relying on nobody adding one.
		h.Set("Service-Worker-Allowed", "")

		next.ServeHTTP(w, r)
	})
}

// NoServiceWorker refuses to serve anything that a browser would accept as a
// service worker script, whatever path it is requested under.
//
// This is belt and braces over "we did not write one": the check is one string
// comparison, and the failure it prevents is a persistent compromise that no
// amount of server-side remediation can reach.
func NoServiceWorker(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.EqualFold(r.Header.Get("Service-Worker"), "script") {
			http.Error(w, "addy serves no service worker", http.StatusNotFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

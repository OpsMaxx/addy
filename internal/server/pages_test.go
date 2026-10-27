package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// WHERE THE SIGN-IN GOES, THE CONSOLE GOES.
//
// The operator routes are mounted whenever a provider is configured, and the
// sign-in they finish lands on /console. The page used to be served only with
// -ui, which is off by default — so a default install with sign-in configured
// completed the sign-in and then showed a 404.
func TestTheConsoleIsServedWheneverSignInIs(t *testing.T) {
	get := func(h http.Handler, path string) int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec.Code
	}

	for _, c := range []struct {
		name   string
		cfg    Config
		signIn bool
		want   map[string]int
	}{
		{
			// The case that was broken.
			name: "sign-in, no -ui", signIn: true,
			want: map[string]int{
				"/console": 200, "/console/relay": 200, "/assets/console.js": 200, "/admin": 302,
				// The masthead's link, sent somewhere real.
				"/": 302,
				// The rest of the portal is still -ui's to serve.
				"/p/abc": 404,
			},
		},
		{
			name: "neither", signIn: false,
			want: map[string]int{"/console": 404, "/": 404, "/assets/console.js": 404},
		},
		{
			name: "-ui", cfg: Config{UI: true}, signIn: false,
			want: map[string]int{"/console": 200, "/": 200, "/p/abc": 200},
		},
	} {
		h, err := pagesFor(c.cfg, c.signIn)
		if err != nil {
			t.Fatal(err)
		}
		for path, want := range c.want {
			if got := get(h, path); got != want {
				t.Errorf("%s: GET %s = %d, want %d", c.name, path, got, want)
			}
		}
	}
}

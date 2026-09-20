package operator

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// A provider, as small as it can be and still be one.
type fakeIDP struct {
	server   *httptest.Server
	subject  string
	email    string
	lastForm map[string]string
}

func newIDP(t *testing.T, subject, email string) *fakeIDP {
	t.Helper()
	idp := &fakeIDP{subject: subject, email: email}
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		base := idp.server.URL
		_ = json.NewEncoder(w).Encode(map[string]string{
			"authorization_endpoint": base + "/auth",
			"token_endpoint":         base + "/token",
			"userinfo_endpoint":      base + "/userinfo",
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		idp.lastForm = map[string]string{}
		for k := range r.Form {
			idp.lastForm[k] = r.Form.Get(k)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "at-" + idp.subject})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer at-"+idp.subject {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"sub": idp.subject, "email": idp.email})
	})

	idp.server = httptest.NewServer(mux)
	t.Cleanup(idp.server.Close)
	return idp
}

// An in-memory instance table.
type memStore struct {
	mu sync.Mutex
	kv map[string]string
}

func newStore() *memStore { return &memStore{kv: map[string]string{}} }

func (m *memStore) InstanceValue(_ context.Context, key string) (string, time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.kv[key], time.Time{}, nil
}

func (m *memStore) SetInstanceValue(_ context.Context, key, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.kv[key] = value
	return nil
}

func authFor(t *testing.T, idp *fakeIDP, store Store) *Auth {
	t.Helper()
	a := New(Config{
		Issuer:       idp.server.URL,
		ClientID:     "cid",
		ClientSecret: "secret",
		BaseURL:      "https://relay.example",
	}, store)
	a.http = idp.server.Client()
	return a
}

// signIn runs a whole round trip and returns the session id.
func signIn(t *testing.T, a *Auth) (string, error) {
	t.Helper()
	where, err := a.Start(context.Background())
	if err != nil {
		return "", err
	}
	// The state is what the provider hands back; take it from the URL this
	// built rather than reaching into the struct.
	at := strings.Index(where, "state=")
	if at < 0 {
		t.Fatalf("no state in %s", where)
	}
	state := where[at+len("state="):]
	if amp := strings.Index(state, "&"); amp >= 0 {
		state = state[:amp]
	}
	return a.Complete(context.Background(), state, "the-code")
}

// ---------------------------------------------------------------------------

func TestUnconfiguredMeansAbsentRatherThanOpen(t *testing.T) {
	// A relay with no provider set must serve NO admin routes. A portal that
	// authenticated nobody would be worse than no portal, and "we will add the
	// check later" is how it would ship open.
	a := New(Config{}, newStore())
	mux := http.NewServeMux()
	a.Routes(mux, nil)

	for _, path := range []string{"/admin/login", "/admin/v1/accounts", "/admin/v1/me"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s answered %d on an unconfigured relay; want 404", path, rec.Code)
		}
	}
}

func TestTheFirstSignInClaimsTheRelayAndTheSecondPersonIsRefused(t *testing.T) {
	// THE WHOLE ACCESS-CONTROL DECISION. Without it, configuring Google would
	// make every Google account in the world an administrator of this relay —
	// which is not a thing anybody would choose on purpose, and is exactly
	// what "sign in with Google" means if nobody writes this rule down.
	store := newStore()

	owner := newIDP(t, "subject-owner", "owner@example.com")
	if _, err := signIn(t, authFor(t, owner, store)); err != nil {
		t.Fatalf("the first sign-in was refused: %v", err)
	}
	if store.kv[OperatorKey] == "" {
		t.Fatal("the first sign-in did not claim the relay")
	}

	// Somebody else at the same provider.
	stranger := newIDP(t, "subject-stranger", "stranger@example.com")
	strangerAuth := New(Config{
		Issuer:       owner.server.URL, // the same issuer this relay was claimed under
		ClientID:     "cid",
		ClientSecret: "secret",
		BaseURL:      "https://relay.example",
	}, store)
	strangerAuth.http = stranger.server.Client()
	// Point discovery at the stranger's provider while keeping the claimed
	// issuer string, which is the closest thing to "a different Google account
	// at the same Google" this test can build.
	strangerAuth.found = &discovery{
		AuthorizationEndpoint: stranger.server.URL + "/auth",
		TokenEndpoint:         stranger.server.URL + "/token",
		UserinfoEndpoint:      stranger.server.URL + "/userinfo",
	}

	if _, err := signIn(t, strangerAuth); err == nil {
		t.Fatal("a second person signed in to a relay somebody else had claimed")
	} else if !strings.Contains(err.Error(), "already has an operator") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}

	// And the owner can still sign in again, or the claim would be a lockout
	// rather than a claim.
	if _, err := signIn(t, authFor(t, owner, store)); err != nil {
		t.Fatalf("the owner was refused from their own relay: %v", err)
	}
}

func TestTheSameIdentifierAtADifferentProviderIsNotTheSamePerson(t *testing.T) {
	// A subject is only unique WITHIN its issuer. Storing the subject alone
	// would mean an operator who switched providers silently matching whoever
	// happened to hold that identifier at the new one.
	store := newStore()
	first := newIDP(t, "1234567890", "a@example.com")
	if _, err := signIn(t, authFor(t, first, store)); err != nil {
		t.Fatal(err)
	}

	second := newIDP(t, "1234567890", "b@elsewhere.example")
	if _, err := signIn(t, authFor(t, second, store)); err == nil {
		t.Fatal("the same subject at a different issuer was treated as the same person")
	}
}

func TestAStateIsGoodOnce(t *testing.T) {
	// Consumed on use, so a replayed callback finds nothing — the back button
	// and an attacker replaying the redirect look the same from here, and both
	// should fail.
	store := newStore()
	idp := newIDP(t, "s", "e@example.com")
	a := authFor(t, idp, store)

	where, err := a.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	state := strings.Split(strings.Split(where, "state=")[1], "&")[0]

	if _, err := a.Complete(context.Background(), state, "code"); err != nil {
		t.Fatalf("the first callback failed: %v", err)
	}
	if _, err := a.Complete(context.Background(), state, "code"); err == nil {
		t.Fatal("the same state was accepted twice")
	}
}

func TestPKCEIsSentAndTheVerifierMatches(t *testing.T) {
	// It costs two lines and removes the class of attack where an intercepted
	// authorization code is redeemed by somebody else.
	store := newStore()
	idp := newIDP(t, "s", "e@example.com")
	a := authFor(t, idp, store)

	where, err := a.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(where, "code_challenge=") || !strings.Contains(where, "code_challenge_method=S256") {
		t.Fatalf("no PKCE challenge in %s", where)
	}
	state := strings.Split(strings.Split(where, "state=")[1], "&")[0]
	if _, err := a.Complete(context.Background(), state, "code"); err != nil {
		t.Fatal(err)
	}
	if idp.lastForm["code_verifier"] == "" {
		t.Fatal("the token exchange sent no code_verifier")
	}
}

func TestASessionEndsAndDoesNotOutliveItsTTL(t *testing.T) {
	store := newStore()
	idp := newIDP(t, "s", "e@example.com")
	a := authFor(t, idp, store)

	sid, err := signIn(t, a)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := a.Session(sid); !ok {
		t.Fatal("a fresh session was not valid")
	}

	a.End(sid)
	if _, ok := a.Session(sid); ok {
		t.Fatal("a session survived being ended")
	}

	sid2, err := signIn(t, a)
	if err != nil {
		t.Fatal(err)
	}
	a.now = func() time.Time { return time.Now().Add(sessionTTL + time.Minute) }
	if _, ok := a.Session(sid2); ok {
		t.Fatal("an expired session was accepted")
	}
}

func TestAnUnauthenticatedCallerReachesNothingButMe(t *testing.T) {
	store := newStore()
	idp := newIDP(t, "s", "e@example.com")
	a := authFor(t, idp, store)

	mux := http.NewServeMux()
	a.Routes(mux, nil)

	// `me` answers without a session, because the page needs it to decide
	// whether to show a sign-in button, and that needs no secret.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/v1/me", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/admin/v1/me answered %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), `"signedIn":true`) {
		t.Fatal("an unauthenticated caller was reported as signed in")
	}

	// Everything else refuses.
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/admin/v1/accounts"},
		{http.MethodPost, "/admin/v1/invite"},
		{http.MethodDelete, "/admin/v1/accounts/abc"},
	} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, nil))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s answered %d without a session; want 401", c.method, c.path, rec.Code)
		}
	}
}

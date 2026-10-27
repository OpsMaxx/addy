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
	name     string
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
		_ = json.NewEncoder(w).Encode(map[string]string{"sub": idp.subject, "email": idp.email, "name": idp.name})
	})

	idp.server = httptest.NewServer(mux)
	t.Cleanup(idp.server.Close)
	return idp
}

// An in-memory instance table.
type memStore struct {
	mu      sync.Mutex
	kv      map[string]string
	users   map[string]*User
	blocked map[string]bool
}

func newStore() *memStore {
	return &memStore{kv: map[string]string{}, users: map[string]*User{}, blocked: map[string]bool{}}
}

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

// Everybody who signs in becomes a user, operator included — an operator is a
// user who also claimed the relay, not a separate kind of thing.
func (m *memStore) UpsertUser(_ context.Context, issuer, subject, email, name string) (*User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := issuer + "\x00" + subject
	if m.users == nil {
		m.users = map[string]*User{}
	}
	if u, ok := m.users[k]; ok {
		u.Email, u.Name = email, name
		return u, nil
	}
	u := &User{UserID: "u-" + subject, Email: email, Name: name, Blocked: m.blocked[k]}
	m.users[k] = u
	return u, nil
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

	// A RELAY IS MULTI-USER, so somebody else signing in is an ordinary user
	// rather than an intruder. What the claim decides is who gets the CONSOLE.
	sid, err := signIn(t, strangerAuth)
	if err != nil {
		t.Fatalf("a second person could not sign in at all: %v", err)
	}
	who, ok := strangerAuth.Session(sid)
	if !ok {
		t.Fatal("the second person got no session")
	}
	if who.Operator {
		t.Fatal("a second person was made operator of a relay somebody else had claimed")
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
	sid, err := signIn(t, authFor(t, second, store))
	if err != nil {
		t.Fatal(err)
	}
	who, _ := authFor(t, second, store).Session(sid)
	_ = who
	// The claim is stored as issuer AND subject, so the same identifier at a
	// different issuer is a different person and does not inherit the console.
	held := store.kv[OperatorKey]
	if !strings.HasPrefix(held, first.server.URL+"\x00") {
		t.Fatalf("the claim moved to the second issuer: %q", held)
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

func TestThePolicyDecidesWhoMintsTheirOwnFirstInvite(t *testing.T) {
	// ON `invite`, A STRANGER AT THE PROVIDER GETS NO STORAGE.
	//
	// For a while everybody signed in could mint, on every policy, which made
	// the default `invite` behave exactly like `open`: anybody with an account
	// at the identity provider got space on somebody's private box. The goal of
	// that change survives -- somebody the operator has ADMITTED sets up their
	// own first device without the operator pressing a button for them.
	for _, c := range []struct {
		policy   SignupPolicy
		admitted bool
		user     int // what an ordinary user gets from POST /admin/v1/my/invite
		op       int // what the operator gets
	}{
		{SignupOpen, false, http.StatusOK, http.StatusOK},
		{SignupInvite, false, http.StatusForbidden, http.StatusOK},
		{SignupInvite, true, http.StatusOK, http.StatusOK},
	} {
		store := newStore()
		owner := newIDP(t, "the-owner", "owner@example.com")

		opAuth := New(Config{
			Issuer: owner.server.URL, ClientID: "cid", ClientSecret: "s",
			BaseURL: "https://relay.example", Signup: c.policy,
		}, store)
		opAuth.http = owner.server.Client()

		opSid, err := signIn(t, opAuth)
		if err != nil {
			t.Fatalf("%s: the operator could not sign in: %v", c.policy, err)
		}

		other := newIDP(t, "somebody-else", "other@example.com")
		userAuth := New(Config{
			Issuer: owner.server.URL, ClientID: "cid", ClientSecret: "s",
			BaseURL: "https://relay.example", Signup: c.policy,
		}, store)
		userAuth.http = other.server.Client()
		userAuth.found = &discovery{
			AuthorizationEndpoint: other.server.URL + "/auth",
			TokenEndpoint:         other.server.URL + "/token",
			UserinfoEndpoint:      other.server.URL + "/userinfo",
		}
		userSid, err := signIn(t, userAuth)
		if err != nil {
			t.Fatalf("%s: an ordinary user could not sign in: %v", c.policy, err)
		}

		mux := http.NewServeMux()
		admin := &blockingAdmin{}
		if c.admitted {
			admin.admitted = map[string]bool{userAuth.sessions[key(userSid)].userID: true}
		}
		opAuth.Routes(mux, admin)

		for _, who := range []struct {
			name string
			sid  string
			want int
		}{{"user", userSid, c.user}, {"operator", opSid, c.op}} {
			req := httptest.NewRequest(http.MethodPost, "/admin/v1/my/invite", nil)
			req.AddCookie(&http.Cookie{Name: cookieName, Value: who.sid})
			rec := httptest.NewRecorder()
			// Both sessions live in opAuth's map, so route through it.
			if who.name == "user" {
				opAuth.mu.Lock()
				opAuth.sessions[key(who.sid)] = userAuth.sessions[key(who.sid)]
				opAuth.mu.Unlock()
			}
			mux.ServeHTTP(rec, req)
			if rec.Code != who.want {
				t.Fatalf("%s policy (admitted %v), %s asking for an invite: got %d want %d (%s)",
					c.policy, c.admitted, who.name, rec.Code, who.want, rec.Body.String())
			}
		}
	}
}

func TestAnOrdinaryUserCannotReachTheOperatorRoutes(t *testing.T) {
	// Two middlewares rather than a boolean argument, because a boolean at a
	// call site is a thing somebody passes wrongly and nothing notices until an
	// ordinary user can delete somebody's account.
	store := newStore()
	owner := newIDP(t, "the-owner", "owner@example.com")
	a := New(Config{
		Issuer: owner.server.URL, ClientID: "cid", ClientSecret: "s",
		BaseURL: "https://relay.example", Signup: SignupOpen,
	}, store)
	a.http = owner.server.Client()
	if _, err := signIn(t, a); err != nil {
		t.Fatal(err)
	}

	// Forge a session for somebody who is not the operator, which is exactly
	// what a second person signing in produces.
	a.mu.Lock()
	a.sessions[key("user-session")] = session{userID: "u-2", email: "x@example.com", operator: false, expires: a.now().Add(time.Hour)}
	a.mu.Unlock()

	mux := http.NewServeMux()
	a.Routes(mux, stubAdmin{})

	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/admin/v1/accounts"},
		{http.MethodGet, "/admin/v1/users"},
		{http.MethodPost, "/admin/v1/invite"},
		{http.MethodDelete, "/admin/v1/accounts/abc"},
		{http.MethodPost, "/admin/v1/users/u-1/blocked"},
	} {
		req := httptest.NewRequest(c.method, c.path, nil)
		req.AddCookie(&http.Cookie{Name: cookieName, Value: "user-session"})
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s %s as an ordinary user answered %d; want 403", c.method, c.path, rec.Code)
		}
	}

	// And their own space still works, or the separation would just be a wall.
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/my/accounts", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: "user-session"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("an ordinary user could not see their own accounts: %d", rec.Code)
	}
}

// stubAdmin answers everything successfully and remembers nothing.
type stubAdmin struct{}

func (stubAdmin) NewInviteFor(context.Context, string, time.Duration) (string, error) {
	return "an-invite", nil
}
func (stubAdmin) Accounts(context.Context) ([]AccountView, error)           { return nil, nil }
func (stubAdmin) AccountsOf(context.Context, string) ([]AccountView, error) { return nil, nil }
func (stubAdmin) Users(context.Context) ([]UserView, error)                 { return nil, nil }
func (stubAdmin) SetQuota(context.Context, string, int64) error             { return nil }
func (stubAdmin) DeleteAccount(context.Context, string) error               { return nil }
func (stubAdmin) SetUserBlocked(context.Context, string, bool) error        { return nil }
func (stubAdmin) SetUserAdmitted(context.Context, string, bool) error       { return nil }
func (stubAdmin) UserAdmitted(context.Context, string) (bool, error)        { return false, nil }

// The operator changes the sign-in policy from the console, and it takes
// effect without a restart.
//
// THE ENVIRONMENT IS A DEFAULT, NOT AN OVERRIDE. An operator making this
// choice in the console has decided at least as deliberately as whoever wrote
// the unit file, and a restart quietly undoing it would be a trap. So the
// stored value wins, and the console says which of the two is in force.
func TestTheOperatorChangesTheSignupPolicyFromTheConsole(t *testing.T) {
	store := newStore()
	owner := newIDP(t, "the-owner", "owner@example.com")
	a := New(Config{
		Issuer: owner.server.URL, ClientID: "cid", ClientSecret: "s",
		BaseURL: "https://relay.example", Signup: SignupOpen,
	}, store)
	a.http = owner.server.Client()

	opSid, err := signIn(t, a)
	if err != nil {
		t.Fatalf("the operator could not sign in: %v", err)
	}
	mux := http.NewServeMux()
	a.Routes(mux, stubAdmin{})

	ask := func(method, path, sid string) (int, string) {
		req := httptest.NewRequest(method, path, nil)
		if method != http.MethodGet {
			req.Header.Set("Origin", "https://relay.example")
		}
		if sid != "" {
			req.AddCookie(&http.Cookie{Name: cookieName, Value: sid})
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}

	// Before anything is stored, the environment is what is in force and the
	// console says so.
	code, body := ask(http.MethodGet, "/admin/v1/settings", opSid)
	if code != http.StatusOK || !strings.Contains(body, `"signupSource":"environment"`) {
		t.Fatalf("settings before any change: %d %s", code, body)
	}
	if a.SignupInForce(context.Background()) != SignupOpen {
		t.Fatalf("in force before any change = %q, want open", a.SignupInForce(context.Background()))
	}

	if code, body = ask(http.MethodPost, "/admin/v1/settings?signup=closed", opSid); code != http.StatusOK {
		t.Fatalf("setting the policy: %d %s", code, body)
	}
	// No restart, no re-read of config: the next question gets the new answer.
	if got := a.SignupInForce(context.Background()); got != SignupClosed {
		t.Fatalf("in force after the change = %q, want closed", got)
	}
	if code, body = ask(http.MethodGet, "/admin/v1/settings", opSid); !strings.Contains(body, `"signupSource":"console"`) {
		t.Fatalf("settings after the change should say it came from the console: %d %s", code, body)
	}

	// A value that is not a policy is refused rather than stored and ignored
	// later, which would leave the console showing one thing and the relay
	// doing another.
	if code, _ = ask(http.MethodPost, "/admin/v1/settings?signup=banana", opSid); code != http.StatusBadRequest {
		t.Errorf("a nonsense policy answered %d, want 400", code)
	}
	if got := a.SignupInForce(context.Background()); got != SignupClosed {
		t.Errorf("a refused write changed the policy to %q", got)
	}

	// A MEMBER CANNOT REACH IT AT ALL. Changing who may sign in is the
	// operator's decision, and a member who could make it could open the relay
	// to everybody.
	memberSid := "a-members-session"
	a.mu.Lock()
	a.sessions[key(memberSid)] = session{subject: "somebody-else", userID: "u2", expires: a.now().Add(time.Hour)}
	a.mu.Unlock()
	if code, _ = ask(http.MethodGet, "/admin/v1/settings", memberSid); code != http.StatusForbidden {
		t.Errorf("a member reading settings got %d, want 403", code)
	}
	if code, _ = ask(http.MethodPost, "/admin/v1/settings?signup=open", memberSid); code != http.StatusForbidden {
		t.Errorf("a member writing settings got %d, want 403", code)
	}
	if got := a.SignupInForce(context.Background()); got != SignupClosed {
		t.Errorf("a member's refused write changed the policy to %q", got)
	}
}

// THE SIGN-IN LANDS ON A PAGE, AND THE PAGE CAN NAME WHO ARRIVED.
//
// Two defects a person with no email met one after the other. The callback
// sent them to /admin, an alias that only the -ui portal answered — so on a
// default install a sign-in that had worked ended on a 404. And once they
// reached the console, the bar named them by a raw user id, because `me`
// carried an email they did not have and not the name the provider did send.
func TestTheSignInLandsOnTheConsoleAndNamesSomebodyWithNoEmail(t *testing.T) {
	idp := newIDP(t, "no-email", "")
	idp.name = "Ada Lovelace"
	a := authFor(t, idp, newStore())
	mux := http.NewServeMux()
	a.Routes(mux, nil)

	where, err := a.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	state := where[strings.Index(where, "state=")+len("state="):]
	if amp := strings.Index(state, "&"); amp >= 0 {
		state = state[:amp]
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/callback?state="+state+"&code=c", nil))
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/console" {
		t.Fatalf("the callback answered %d to %q; it has to land on /console, the page that is served wherever this route is",
			rec.Code, rec.Header().Get("Location"))
	}
	var sid string
	for _, c := range rec.Result().Cookies() {
		if c.Name == cookieName {
			sid = c.Value
		}
	}
	if sid == "" {
		t.Fatal("the callback set no session cookie")
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/me", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: sid})
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var me struct {
		SignedIn bool   `json:"signedIn"`
		Name     string `json:"name"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &me); err != nil {
		t.Fatal(err)
	}
	if !me.SignedIn || me.Name != "Ada Lovelace" {
		t.Fatalf("me = %s; the bar falls back to the name when there is no email, so it has to be there", rec.Body.String())
	}
}

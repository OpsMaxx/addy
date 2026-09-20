package operator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The whole console, cell by cell: who is asking, what the relay's signup
// policy is, and every route the two pages call.
//
// The existing tests each pin one rule. This pins the GRID, because the defect
// that gets through a set of single-rule tests is the combination nobody wrote
// a test for — a route that is right for a member on an open relay and wrong
// for the same member once the policy changes, or right for the operator and
// reachable by everybody. Every cell carries the reason its code is the right
// one, so a diff that changes a number has to argue with a sentence.

// who is asking.
const (
	anonymous = iota
	member
	operator
)

// aRelay is one configured relay with a session of each kind already in it.
type aRelay struct {
	auth     *Auth
	mux      *http.ServeMux
	store    *memStore
	admin    *blockingAdmin
	opSid    string
	opID     string
	memSid   string
	memID    string
	memberIs string // issuer\x00subject, to reach the member's store row
	// Somebody with a store row and NO session, for the routes that change a
	// named person. See relayWith.
	spareID string
	// The member's own provider, sharing this relay's store and issuer. It is
	// how a test asks what happens when the member signs in AGAIN, which is a
	// different question from what their existing session can do.
	memAuth *Auth
}

// relayWith builds a relay on the given policy with an operator and a member
// signed in.
//
// The member's session is forged into the map rather than signed in, for one
// reason worth writing down: on a `closed` relay nobody but the operator can
// complete a sign-in, so there is no other way to ask what the ROUTES do for a
// member there. That matters because the routes must not be relying on the
// sign-in to enforce the policy — the policy is a flag, so today a change to
// it restarts the process and clears every session, and the day somebody makes
// it reloadable is the day that assumption becomes a hole.
func relayWith(t *testing.T, policy SignupPolicy) *aRelay {
	t.Helper()
	store := newStore()
	idp := newIDP(t, "the-owner", "owner@example.com")
	a := New(Config{
		Issuer: idp.server.URL, ClientID: "cid", ClientSecret: "s",
		BaseURL: "https://relay.example", Signup: policy,
	}, store)
	a.http = idp.server.Client()

	opSid, err := signIn(t, a)
	if err != nil {
		t.Fatalf("%s: the operator could not sign in: %v", policy, err)
	}
	who, ok := a.Session(opSid)
	if !ok || !who.Operator {
		t.Fatalf("%s: the first sign-in did not produce an operator", policy)
	}

	// A second person, as a sign-in on an open or invite relay produces one.
	// Their provider keeps this relay's issuer string while discovery points
	// at a different server, which is the closest thing to "another account at
	// the same Google" these tests can build.
	other := newIDP(t, "somebody-else", "other@example.com")
	memAuth := New(Config{
		Issuer: idp.server.URL, ClientID: "cid", ClientSecret: "s",
		BaseURL: "https://relay.example", Signup: policy,
	}, store)
	memAuth.http = other.server.Client()
	memAuth.found = &discovery{
		AuthorizationEndpoint: other.server.URL + "/auth",
		TokenEndpoint:         other.server.URL + "/token",
		UserinfoEndpoint:      other.server.URL + "/userinfo",
	}

	memberIs := idp.server.URL + "\x00somebody-else"
	memUser, err := store.UpsertUser(context.Background(), idp.server.URL, "somebody-else", "other@example.com", "")
	if err != nil {
		t.Fatal(err)
	}

	// A third person with a row and NO session, for the routes that change a
	// named person. Blocking now ends that person's live sessions, so a matrix
	// cell aimed at the member would sign the member out and every member cell
	// running after it would answer 401 instead of the 403 it was written for
	// — a failure that moves when the cells reorder. Aiming at somebody with
	// nothing to end keeps each cell's precondition stated rather than
	// repaired afterwards.
	spare, err := store.UpsertUser(context.Background(), idp.server.URL, "a-third-person", "spare@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	a.sessions[key("a-members-session")] = session{
		subject: "somebody-else", email: memUser.Email, userID: memUser.UserID,
		operator: false, expires: a.now().Add(time.Hour),
	}
	a.mu.Unlock()

	admin := &blockingAdmin{}
	mux := http.NewServeMux()
	a.Routes(mux, admin)
	return &aRelay{
		auth: a, mux: mux, store: store, admin: admin,
		opSid: opSid, opID: who.UserID,
		memSid: "a-members-session", memID: memUser.UserID, memberIs: memberIs,
		spareID: spare.UserID,
		memAuth: memAuth,
	}
}

// ask makes one request as one of the three callers and returns the status.
func (r *aRelay) ask(t *testing.T, as int, method, path string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	switch as {
	case member:
		req.AddCookie(&http.Cookie{Name: cookieName, Value: r.memSid})
	case operator:
		req.AddCookie(&http.Cookie{Name: cookieName, Value: r.opSid})
	}
	rec := httptest.NewRecorder()
	r.mux.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func nameOf(as int) string {
	return [...]string{"an anonymous caller", "a member", "the operator"}[as]
}

func TestEveryConsoleRouteForEveryCallerOnEveryPolicy(t *testing.T) {
	// `{id}` is filled with a real person who has no session, so the operator
	// rows exercise a row that exists rather than a 404 path, and no cell
	// changes what a later cell reads.
	cells := []struct {
		method, path string
		anon         int
		member       int
		// A member's answer where the difference is the policy rather than the
		// caller. Zero means "the same on every policy".
		memberIfOpen int
		operator     int
		why          string
	}{
		{
			method: http.MethodGet, path: "/admin/v1/me",
			anon: http.StatusOK, member: http.StatusOK, operator: http.StatusOK,
			why: "the page asks this before it knows whether anybody is signed in, and " +
				"answering `should I show a sign-in button` needs no secret; it is 200 " +
				"with signedIn:false rather than 401 for exactly that reason",
		},
		{
			method: http.MethodGet, path: "/admin/v1/my/accounts",
			anon: http.StatusUnauthorized, member: http.StatusOK, operator: http.StatusOK,
			why: "everybody signed in has their own space, and an operator is a user who " +
				"also claimed the relay rather than a separate kind of thing, so this is " +
				"the same route for both",
		},
		{
			method: http.MethodPost, path: "/admin/v1/my/invite",
			anon: http.StatusUnauthorized, member: http.StatusOK,
			memberIfOpen: http.StatusOK, operator: http.StatusOK,
			why: "SETTING UP YOUR OWN FIRST DEVICE NEEDS NOBODY'S PERMISSION. This used " +
				"to depend on the signup policy, which meant asking an operator to press " +
				"the same button on the same page; the gate protected nothing, because " +
				"whoever could sign in was already somebody this relay had admitted. " +
				"What still holds a person to one device group is the store, and the " +
				"policy now decides only who may sign in at all",
		},
		{
			method: http.MethodGet, path: "/admin/v1/users",
			anon: http.StatusUnauthorized, member: http.StatusForbidden, operator: http.StatusOK,
			why: "the list of everybody on the relay is the operator's; a member learning " +
				"who else is here would be the relay leaking its membership",
		},
		{
			method: http.MethodPost, path: "/admin/v1/users/{id}/blocked?blocked=true",
			anon: http.StatusUnauthorized, member: http.StatusForbidden, operator: http.StatusNoContent,
			why: "blocking is the operator's, and it answers 204 because there is nothing " +
				"to return — the page refetches the list",
		},
		{
			method: http.MethodPost, path: "/admin/v1/invite",
			anon: http.StatusUnauthorized, member: http.StatusForbidden, operator: http.StatusOK,
			why: "an invite for nobody in particular, to hand to somebody who has not " +
				"signed in; a member who wants one asks for /my/invite, which is bound to them",
		},
		{
			method: http.MethodGet, path: "/admin/v1/accounts",
			anon: http.StatusUnauthorized, member: http.StatusForbidden, operator: http.StatusOK,
			why: "every account on the relay. A member reaching this would see other " +
				"people's account identifiers and sizes",
		},
		{
			method: http.MethodPost, path: "/admin/v1/accounts/{id}/quota?bytes=0",
			anon: http.StatusUnauthorized, member: http.StatusForbidden, operator: http.StatusNoContent,
			why: "quota is availability, which is the plane the threat model already " +
				"concedes to whoever runs the box",
		},
		{
			method: http.MethodDelete, path: "/admin/v1/accounts/{id}",
			anon: http.StatusUnauthorized, member: http.StatusForbidden, operator: http.StatusNoContent,
			why: "the most destructive thing the console can do, so it is the one that " +
				"most needs to be 403 for a member rather than 404 or 500",
		},
	}

	for _, policy := range []SignupPolicy{SignupOpen, SignupInvite, SignupClosed} {
		r := relayWith(t, policy)
		for _, c := range cells {
			path := strings.ReplaceAll(c.path, "{id}", r.spareID)
			for _, as := range []int{anonymous, member, operator} {
				want := [...]int{c.anon, c.member, c.operator}[as]
				if as == member && policy == SignupOpen && c.memberIfOpen != 0 {
					want = c.memberIfOpen
				}
				got, body := r.ask(t, as, c.method, path)
				if got != want {
					t.Errorf("%s policy: %s %s as %s answered %d, want %d.\n  why: %s\n  body: %s",
						policy, c.method, c.path, nameOf(as), got, want, c.why, strings.TrimSpace(body))
				}
			}
		}
	}
}

// ---------------------------------------------------------------------------
// The three the console's behaviour actually turns on
// ---------------------------------------------------------------------------

func TestBlockingEndsTheSessionTheBlockedPersonAlreadyHad(t *testing.T) {
	// This case is kept from when it recorded the opposite, because the
	// behaviour is the part worth a regression test and a test named for the
	// old behaviour is how the bug comes back unnoticed.
	//
	// Blocking writes `blocked_at` in the store. Sessions live in memory and
	// the store is read at sign-in, so for a while a block took effect at the
	// blocked person's NEXT sign-in and not on the tab they had open — while
	// the console's confirmation told the operator they had been stopped. The
	// route now ends their sessions, which is what makes that sentence true.
	r := relayWith(t, SignupOpen)

	if code, _ := r.ask(t, member, http.MethodGet, "/admin/v1/my/accounts"); code != http.StatusOK {
		t.Fatalf("the member could not read their own accounts before being blocked: %d", code)
	}
	code, body := r.ask(t, operator, http.MethodPost, "/admin/v1/users/"+r.memID+"/blocked?blocked=true")
	if code != http.StatusNoContent {
		t.Fatalf("blocking answered %d: %s", code, body)
	}
	if !r.admin.blocked[r.memID] {
		t.Fatal("the block never reached the store")
	}
	// The store is what a sign-in reads, so put the person's row in the state
	// a real block leaves it in.
	r.store.mu.Lock()
	r.store.users[r.memberIs].Blocked = true
	r.store.mu.Unlock()

	if _, ok := r.auth.Session(r.memSid); ok {
		t.Error("a blocked person's session is still valid; blocking has to end it, " +
			"or the console's confirmation is promising something that does not happen")
	}
	// `me` is the one route that answers without a session, so it stays 200
	// and reports the truth. That is how the open tab finds out.
	if _, body := r.ask(t, member, http.MethodGet, "/admin/v1/me"); !strings.Contains(body, `"signedIn":false`) {
		t.Errorf("/admin/v1/me still reports a blocked person as signed in: %s", strings.TrimSpace(body))
	}
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/admin/v1/my/accounts"},
		{http.MethodPost, "/admin/v1/my/invite"},
	} {
		if code, _ := r.ask(t, member, c.method, c.path); code != http.StatusUnauthorized {
			t.Errorf("%s %s answered %d with a blocked person's cookie, want 401", c.method, c.path, code)
		}
	}

	// And they cannot get a new session either, which is the other half: the
	// sweep would only move the problem if signing in again handed one back.
	if _, err := signIn(t, r.memAuth); err == nil {
		t.Error("a blocked person signed in again")
	} else if !strings.Contains(err.Error(), "blocked") {
		t.Errorf("a blocked person was refused for the wrong reason: %v", err)
	}

	// Nobody else is caught by the sweep. It matches on the user id, and an id
	// is one person — but a sweep is the kind of thing that is written once
	// and widened later by somebody in a hurry.
	if _, ok := r.auth.Session(r.opSid); !ok {
		t.Error("blocking one person ended somebody else's session")
	}
}

func TestABlockedRowCannotLockTheOperatorOutOfTheirOwnRelay(t *testing.T) {
	// THE ONE NOBODY WILL THINK TO CHECK AGAIN, which is why it is written
	// down rather than left to the fix's own comment.
	//
	// `POST /users/{id}/blocked` refuses to act on yourself, precisely so an
	// operator cannot lock themselves out. But the route is not the only thing
	// that writes that column: an operator tidying the database by hand, or a
	// script, can set it on any row including their own. That produced a
	// PERMANENT lockout that looked fine until the tab was closed — the live
	// session kept working, a fresh sign-in was refused, and the one route
	// that could clear the flag refuses to act on yourself. The remedy was the
	// SQL statement the self-block guard exists to avoid needing.
	//
	// So the exemption is `isOperator`, derived from the claim, rather than a
	// second flag somebody could also set wrongly.
	r := relayWith(t, SignupOpen)
	ownerIs := r.memberIs[:strings.LastIndex(r.memberIs, "\x00")] + "\x00the-owner"

	// Both rows switched off the only way this can happen: out of band.
	r.store.mu.Lock()
	r.store.users[ownerIs].Blocked = true
	r.store.users[r.memberIs].Blocked = true
	r.store.mu.Unlock()

	sid, err := signIn(t, r.auth)
	if err != nil {
		t.Fatalf("a blocked row locked the operator out of their own relay: %v.\n"+
			"There is no way back from here without editing the database, which is "+
			"exactly what the self-block guard exists to avoid needing.", err)
	}
	who, ok := r.auth.Session(sid)
	if !ok || !who.Operator {
		t.Fatalf("the operator signed in but did not get the console back (ok=%v, operator=%v)", ok, who.Operator)
	}
	if code, _ := r.ask(t, operator, http.MethodGet, "/admin/v1/users"); code != http.StatusOK {
		t.Errorf("the operator signed in past a blocked row and still could not use the console: %d", code)
	}

	// The exemption is the operator's alone. Somebody else with an identically
	// blocked row is still refused, or the fix would have turned the flag off
	// for everybody.
	if _, err := signIn(t, r.memAuth); err == nil {
		t.Error("a blocked member signed in; the operator exemption is applying to everybody")
	} else if !strings.Contains(err.Error(), "blocked") {
		t.Errorf("a blocked member was refused for the wrong reason: %v", err)
	}

	// The flag is not cleared by signing in past it. Deleting it would hide
	// that somebody tried, and the console shows it.
	r.store.mu.Lock()
	still := r.store.users[ownerIs].Blocked
	r.store.mu.Unlock()
	if !still {
		t.Error("signing in cleared the operator's blocked flag; it should stay set and stay visible")
	}
}

func TestARowBlockedOutOfBandDoesNotEndASession(t *testing.T) {
	// THE KNOWN LIMIT OF THE FIX ABOVE, pinned so that it is a decision on
	// record rather than something a reader assumes is covered.
	//
	// Sessions are ended by the route that does the blocking, because a store
	// lookup on every authenticated request is a permanent cost paid to catch
	// a rare event that has exactly one trigger. The trigger does the work —
	// so a row switched off by editing the database directly ends nothing,
	// because nothing tells the process it happened. Whoever does that has
	// shell on the box and can restart the relay, which ends every session.
	r := relayWith(t, SignupOpen)

	r.store.mu.Lock()
	r.store.users[r.memberIs].Blocked = true
	r.store.mu.Unlock()

	if _, ok := r.auth.Session(r.memSid); !ok {
		t.Error("a row blocked out of band ended a live session.\n" +
			"Good, but it means sessions are being checked against the store somewhere — " +
			"find out where, because the cost of that is paid on every request.")
	}
	if code, _ := r.ask(t, member, http.MethodGet, "/admin/v1/my/accounts"); code != http.StatusOK {
		t.Errorf("out-of-band block: /admin/v1/my/accounts answered %d, want 200", code)
	}
	// The next sign-in is still refused, so the row is not being ignored — it
	// is only the live session that outlives it.
	if _, err := signIn(t, r.memAuth); err == nil {
		t.Error("a row blocked out of band did not stop the next sign-in")
	}
}

func TestAMemberCannotReachAnotherPersonsAccountsByAnyRouteOrParameter(t *testing.T) {
	// `/my/accounts` takes the user id from the SESSION and has no parameter
	// for one, which is the property worth holding rather than the absence of
	// a particular parameter name. So the test asks for somebody else's data
	// every way the route could be made to take it, and checks that what comes
	// back is still the caller's own.
	r := relayWith(t, SignupOpen)
	r.admin.owned = map[string][]AccountView{
		r.opID:  {{AccountID: "the-operators-account"}},
		r.memID: {{AccountID: "the-members-account"}},
	}

	for _, path := range []string{
		"/admin/v1/my/accounts",
		"/admin/v1/my/accounts?userId=" + r.opID,
		"/admin/v1/my/accounts?user=" + r.opID,
		"/admin/v1/my/accounts?id=" + r.opID,
		"/admin/v1/my/accounts/" + r.opID,
	} {
		code, body := r.ask(t, member, http.MethodGet, path)
		if code == http.StatusNotFound {
			continue // no such route, which is the same answer by other means
		}
		if code != http.StatusOK {
			t.Errorf("GET %s answered %d: %s", path, code, strings.TrimSpace(body))
			continue
		}
		if strings.Contains(body, "the-operators-account") {
			t.Errorf("GET %s handed a member somebody else's accounts: %s", path, strings.TrimSpace(body))
		}
		if !strings.Contains(body, "the-members-account") {
			t.Errorf("GET %s did not return the member's own accounts: %s", path, strings.TrimSpace(body))
		}
	}

	// And the operator-wide listing, which is the only route that answers with
	// everybody's, stays shut.
	if code, _ := r.ask(t, member, http.MethodGet, "/admin/v1/accounts"); code != http.StatusForbidden {
		t.Errorf("a member reached the relay-wide account list: %d", code)
	}
}

func TestTheOperatorCannotBlockThemselvesOutOfTheirOwnRelay(t *testing.T) {
	// An operator who blocks themselves cannot sign in to unblock themselves,
	// and the remedy is a SQL statement on the box — a bad thing to need
	// because of one misplaced click. The console never draws the button, but
	// the console is not what enforces it: this is the same fetch anybody can
	// make by hand, and the refusal has to live on the route.
	for _, policy := range []SignupPolicy{SignupOpen, SignupInvite, SignupClosed} {
		r := relayWith(t, policy)

		code, body := r.ask(t, operator, http.MethodPost, "/admin/v1/users/"+r.opID+"/blocked?blocked=true")
		if code != http.StatusBadRequest {
			t.Errorf("%s policy: the operator blocking themselves answered %d, want 400: %s",
				policy, code, strings.TrimSpace(body))
		}
		if r.admin.blocked[r.opID] {
			t.Errorf("%s policy: the operator was blocked anyway", policy)
		}
		// Still the operator afterwards, or the refusal would only be cosmetic.
		if code, _ := r.ask(t, operator, http.MethodGet, "/admin/v1/users"); code != http.StatusOK {
			t.Errorf("%s policy: the operator lost the console after a refused self-block: %d", policy, code)
		}
		// Unblocking themselves is the same request with the other value and is
		// refused for the same reason, which is right: there is nothing to undo.
		if code, _ := r.ask(t, operator, http.MethodPost,
			"/admin/v1/users/"+r.opID+"/blocked?blocked=false"); code != http.StatusBadRequest {
			t.Errorf("%s policy: the operator unblocking themselves answered %d, want 400", policy, code)
		}
	}
}

// ---------------------------------------------------------------------------

// blockingAdmin remembers what it was told, so a test can ask whether a refusal
// happened before the store or after it. Everything else answers successfully,
// like stubAdmin.
type blockingAdmin struct {
	stubAdmin
	blocked map[string]bool
	owned   map[string][]AccountView
}

func (b *blockingAdmin) SetUserBlocked(_ context.Context, userID string, blocked bool) error {
	if b.blocked == nil {
		b.blocked = map[string]bool{}
	}
	b.blocked[userID] = blocked
	return nil
}

func (b *blockingAdmin) AccountsOf(_ context.Context, userID string) ([]AccountView, error) {
	return b.owned[userID], nil
}

// The real store refuses to mint for somebody it has marked blocked, which is
// the one thing that stops a blocked person's live session doing damage.
func (b *blockingAdmin) NewInviteFor(_ context.Context, userID string, _ time.Duration) (string, error) {
	if b.blocked[userID] {
		return "", errBlocked
	}
	return "an-invite", nil
}

var errBlocked = &blockedError{}

type blockedError struct{}

func (*blockedError) Error() string { return "store: that user is blocked" }

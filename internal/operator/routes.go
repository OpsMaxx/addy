package operator

import (
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// THE STATUS CODE IS PART OF THE CONTRACT, so the HTTP layer needs to tell a
// missing row from a refusal from a genuine fault. It cannot import the store
// to compare sentinels — the whole point of the Admin interface is that this
// package does not know what is behind it — so the seam translates instead,
// and these are what it translates into. An error matching neither is a 500,
// which is the right answer for something nobody anticipated.
var (
	// ErrNotFound is a row that is not there. A 404, not a 500: an operator
	// clicking Block on a row another tab already deleted has made an ordinary
	// mistake, not triggered a server fault.
	ErrNotFound = errors.New("operator: no such thing")
	// ErrBlocked is a person the operator has switched off. A 403 carrying the
	// reason, not a 500 carrying the store's internal layering.
	ErrBlocked = errors.New("operator: that account is blocked")
)

// fault maps an error to the status code that describes it, and to a sentence
// written for whoever reads it.
//
// The raw error goes out only for the codes that mean "this relay is broken".
// For the two anticipated cases it does not, because those strings are built
// for a maintainer: a blocked person was shown
// "store: storing the invite: store: that user is blocked", which names three
// layers and no remedy.
func fault(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		problem(w, http.StatusNotFound, errors.New("there is nothing here by that name; it may have been deleted"))
	case errors.Is(err, ErrBlocked):
		problem(w, http.StatusForbidden, errors.New("this account has been blocked on this relay; ask whoever runs it"))
	default:
		problem(w, http.StatusInternalServerError, err)
	}
}

// Admin is what the portal can do once somebody is signed in.
//
// Every method here is something a person with SSH to this box can already do
// with `addy` on the command line. The portal removes the SSH, not a boundary
// — which is the test any method added later has to pass.
type Admin interface {
	// NewInviteFor mints an invite bound to a person, so the account that
	// spends it is attributed without anybody claiming it. An empty userID
	// mints one for nobody, which is right for handing to somebody who has
	// not signed in.
	NewInviteFor(ctx context.Context, userID string, ttl time.Duration) (string, error)
	Accounts(ctx context.Context) ([]AccountView, error)
	AccountsOf(ctx context.Context, userID string) ([]AccountView, error)
	Users(ctx context.Context) ([]UserView, error)
	SetQuota(ctx context.Context, accountID string, bytes int64) error
	DeleteAccount(ctx context.Context, accountID string) error
	SetUserBlocked(ctx context.Context, userID string, blocked bool) error
}

// UserView is a person as the console lists them.
//
// Same absence as AccountView, for the same reason: a person has accounts,
// those accounts hold bytes, and that is everything this relay knows. No
// device name — the relay holds no key and cannot read one.
type UserView struct {
	UserID    string `json:"userId"`
	Email     string `json:"email"`
	Name      string `json:"name,omitempty"`
	CreatedAt string `json:"createdAt"`
	LastSeen  string `json:"lastSeen,omitempty"`
	Accounts  int    `json:"accounts"`
	UsedBytes int64  `json:"usedBytes"`
	QuotaByte int64  `json:"quotaBytes"`
	Blocked   bool   `json:"blocked"`
	Operator  bool   `json:"operator,omitempty"`
}

// AccountView is what an operator sees, and what they deliberately do not.
//
// No label, no device name, no collection contents — a device is a public key
// and a last-seen time, which is what the threat model already concedes the
// server knows. Anything more would mean the server had learned something the
// design spends its length promising it cannot.
type AccountView struct {
	AccountID string `json:"accountId"`
	// The email of whoever owns it, or empty.
	//
	// Empty is a real answer and not a lookup failure: an account registered
	// with an invite that named nobody belongs to nobody until somebody claims
	// it, and every account created before there were users is in that state.
	// The page prints a dash rather than "unknown", which would suggest the
	// relay had lost track of something it never knew.
	Owner     string `json:"owner,omitempty"`
	CreatedAt string `json:"createdAt"`
	Devices   int    `json:"devices"`
	UsedBytes int64  `json:"usedBytes"`
	QuotaByte int64  `json:"quotaBytes"`
	LastSeen  string `json:"lastSeen,omitempty"`
}

const cookieName = "addy_operator"

// Routes mounts the operator portal onto a mux.
//
// Nothing is mounted when the provider is not configured. A relay with no
// operator portal is a relay you administer over SSH, which is where it
// started; a portal that authenticated nobody would be worse than none.
func (a *Auth) Routes(mux *http.ServeMux, admin Admin) {
	if !a.cfg.Enabled() {
		return
	}

	mux.HandleFunc("GET /admin/login", func(w http.ResponseWriter, r *http.Request) {
		where, err := a.Start(r.Context())
		if err != nil {
			turnedAway(w, http.StatusBadGateway, err)
			return
		}
		http.Redirect(w, r, where, http.StatusFound)
	})

	mux.HandleFunc("GET /admin/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if e := q.Get("error"); e != "" {
			// The provider's own refusal, shown as itself. "Something went
			// wrong" would leave somebody unable to tell a cancelled sign-in
			// from a misconfigured client id.
			turnedAway(w, http.StatusForbidden, errors.New("the provider refused the sign-in: "+e))
			return
		}
		sid, err := a.Complete(r.Context(), q.Get("state"), q.Get("code"))
		if err != nil {
			turnedAway(w, http.StatusForbidden, err)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:  cookieName,
			Value: sid,
			Path:  "/",
			// Lax rather than Strict: the cookie is set on the redirect BACK
			// from the provider, and Strict would withhold it on exactly that
			// navigation — the user would land signed in and be told they are
			// not.
			SameSite: http.SameSiteLaxMode,
			HttpOnly: true,
			Secure:   true,
			MaxAge:   int(sessionTTL / time.Second),
		})
		http.Redirect(w, r, "/admin", http.StatusFound)
	})

	mux.HandleFunc("POST /admin/logout", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie(cookieName); err == nil {
			a.End(c.Value)
		}
		http.SetCookie(w, &http.Cookie{
			Name: cookieName, Value: "", Path: "/", MaxAge: -1,
			HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
		})
		w.WriteHeader(http.StatusNoContent)
	})

	// Who is signed in, for the page to render itself. Unauthenticated and
	// deliberately empty when nobody is: it answers "should I show the sign-in
	// button", and answering that needs no secret.
	mux.HandleFunc("GET /admin/v1/me", func(w http.ResponseWriter, r *http.Request) {
		who, ok := a.current(r)
		body := map[string]any{
			"signedIn": ok,
			"email":    who.Email,
			// THE PAGE NAMES PEOPLE BY IDENTITY, NOT BY EMAIL. An OIDC
			// provider need not return an email at all, and when it does not,
			// every person on the relay compares equal to every other — which
			// is how the console came to render a "you" chip on every row and
			// a Block button on none. The store keys people on (issuer,
			// subject) and hands out this id precisely so there is something
			// stable to compare.
			"userId": who.UserID,
			// The page renders one of two consoles off this. An operator gets
			// the whole relay; everybody else gets their own space, which is
			// the same shape with one row in it.
			"operator": who.Operator,
		}
		// THE POLICY IS NOT ANONYMOUS INFORMATION. It tells a stranger whether
		// this relay hands out accounts on request, which is a reason to come
		// back and a thing to enumerate across relays. The page only needs it
		// once somebody is signed in, because it decides whether to draw a
		// button they could use — and portal.go states that /v1/meta is
		// deliberately the only structured thing served without a session.
		if ok {
			body["signup"] = string(a.cfg.Signup)
		}
		writeJSON(w, body)
	})

	// ---- anybody signed in: their own space --------------------------------

	mux.Handle("GET /admin/v1/my/accounts", a.signedIn(func(w http.ResponseWriter, r *http.Request, who Signed) {
		list, err := admin.AccountsOf(r.Context(), who.UserID)
		if err != nil {
			fault(w, err)
			return
		}
		writeJSON(w, map[string]any{"accounts": list})
	}))

	mux.Handle("POST /admin/v1/my/invite", a.signedIn(func(w http.ResponseWriter, r *http.Request, who Signed) {
		// THE POLICY IS ENFORCED HERE, not in the page. A page that hid the
		// button would be a page somebody could bypass with one fetch.
		if !who.Operator && a.cfg.Signup != SignupOpen {
			problem(w, http.StatusForbidden, errors.New(
				"this relay does not hand out invites; ask whoever runs it for one"))
			return
		}
		token, err := admin.NewInviteFor(r.Context(), who.UserID, 24*time.Hour)
		if err != nil {
			fault(w, err)
			return
		}
		writeJSON(w, map[string]any{"invite": token, "hours": 24})
	}))

	// ---- the operator: the whole relay -------------------------------------

	mux.Handle("GET /admin/v1/users", a.operator(func(w http.ResponseWriter, r *http.Request, _ Signed) {
		list, err := admin.Users(r.Context())
		if err != nil {
			fault(w, err)
			return
		}
		writeJSON(w, map[string]any{"users": list})
	}))

	mux.Handle("POST /admin/v1/users/{id}/blocked", a.operator(func(w http.ResponseWriter, r *http.Request, who Signed) {
		blocked := r.URL.Query().Get("blocked") != "false"
		if r.PathValue("id") == who.UserID {
			// Refused rather than allowed with a warning. An operator who
			// blocks themselves cannot sign in to unblock themselves, and the
			// remedy is a SQL statement on the box — which is a bad thing to
			// need because of one misplaced click.
			problem(w, http.StatusBadRequest, errors.New("you cannot block yourself"))
			return
		}
		if err := admin.SetUserBlocked(r.Context(), r.PathValue("id"), blocked); err != nil {
			fault(w, err)
			return
		}
		// THE FLAG ALONE DOES NOT STOP ANYBODY WHO IS ALREADY SIGNED IN.
		// Sessions are held in memory and the store is read at sign-in, so a
		// block used to take effect at the blocked person's NEXT sign-in and
		// not on the tab they had open — while the console's own confirmation
		// told the operator they had been stopped. Ending their sessions here
		// is what makes that sentence true.
		if blocked {
			a.EndAllFor(r.PathValue("id"))
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	mux.Handle("POST /admin/v1/invite", a.operator(func(w http.ResponseWriter, r *http.Request, _ Signed) {
		hours, _ := strconv.Atoi(r.URL.Query().Get("hours"))
		if hours <= 0 || hours > 24*30 {
			hours = 24
		}
		// For nobody in particular: the operator is handing this to somebody
		// who may not have signed in yet, so the account it creates belongs to
		// nobody until they do.
		token, err := admin.NewInviteFor(r.Context(), "", time.Duration(hours)*time.Hour)
		if err != nil {
			fault(w, err)
			return
		}
		// The token is returned ONCE and never stored anywhere this page can
		// read again, which is why the UI copies it immediately and says so.
		writeJSON(w, map[string]any{"invite": token, "hours": hours})
	}))

	mux.Handle("GET /admin/v1/accounts", a.operator(func(w http.ResponseWriter, r *http.Request, _ Signed) {
		list, err := admin.Accounts(r.Context())
		if err != nil {
			fault(w, err)
			return
		}
		writeJSON(w, map[string]any{"accounts": list})
	}))

	mux.Handle("POST /admin/v1/accounts/{id}/quota", a.operator(func(w http.ResponseWriter, r *http.Request, _ Signed) {
		bytes, err := strconv.ParseInt(r.URL.Query().Get("bytes"), 10, 64)
		if err != nil || bytes < 0 {
			problem(w, http.StatusBadRequest, errors.New("bytes is a non-negative number; 0 means unlimited"))
			return
		}
		if err := admin.SetQuota(r.Context(), r.PathValue("id"), bytes); err != nil {
			fault(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	mux.Handle("DELETE /admin/v1/accounts/{id}", a.operator(func(w http.ResponseWriter, r *http.Request, _ Signed) {
		if err := admin.DeleteAccount(r.Context(), r.PathValue("id")); err != nil {
			fault(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
}

func (a *Auth) current(r *http.Request) (Signed, bool) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return Signed{}, false
	}
	return a.Session(c.Value)
}

// signedIn admits anybody with a session. operator admits only the person who
// claimed the relay. TWO MIDDLEWARES rather than a boolean argument, because a
// boolean at a call site is a thing somebody passes wrongly and nothing
// notices until an ordinary user can delete an account.
func (a *Auth) signedIn(next func(http.ResponseWriter, *http.Request, Signed)) http.Handler {
	return a.guard(false, next)
}

func (a *Auth) operator(next func(http.ResponseWriter, *http.Request, Signed)) http.Handler {
	return a.guard(true, next)
}

func (a *Auth) guard(needOperator bool, next func(http.ResponseWriter, *http.Request, Signed)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		who, ok := a.current(r)
		if !ok {
			problem(w, http.StatusUnauthorized, errors.New("sign in first"))
			return
		}
		if needOperator && !who.Operator {
			problem(w, http.StatusForbidden, errors.New("only this relay's operator can do that"))
			return
		}
		// A state-changing request has to be same-origin. The session cookie
		// is SameSite=Lax, which covers form posts from another site but NOT
		// a top-level navigation — so this is the second line, and it is the
		// one that holds for `fetch` with credentials.
		if r.Method != http.MethodGet {
			origin := r.Header.Get("Origin")
			if origin != "" && !strings.EqualFold(origin, strings.TrimSuffix(a.cfg.BaseURL, "/")) {
				problem(w, http.StatusForbidden, errors.New("that request did not come from this portal"))
				return
			}
		}
		next(w, r, who)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

// turnedAway renders a refusal for a BROWSER NAVIGATION rather than for a
// fetch.
//
// /admin/callback is reached by the provider redirecting a person's browser to
// it, so whatever it writes is what they see in the window — and it wrote
// JSON. Somebody turned away by the signup policy, somebody blocked, and
// anybody who pressed the back button all landed on a blank white page reading
// {"error":"this relay is not open for sign-in; ask whoever runs it"}. That
// sentence was written for a human; it just was not being shown to one.
//
// The markup is deliberately tiny and carries no script and no inline style,
// so it needs nothing from the Content-Security-Policy that the rest of the
// portal does not already allow.
func turnedAway(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	page := `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex, nofollow">
<title>Not signed in</title>
<link rel="stylesheet" href="/assets/portal.css"></head>
<body><main class="wrap">
<h1>Not signed in</h1>
<p class="problem">` + template.HTMLEscapeString(err.Error()) + `</p>
<p><a class="button ghost" href="/">Back to the relay</a></p>
</main></body></html>`
	_, _ = io.WriteString(w, page)
}

func problem(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

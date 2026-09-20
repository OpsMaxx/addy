package operator

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

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
			problem(w, http.StatusBadGateway, err)
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
			problem(w, http.StatusForbidden, errors.New("the provider refused the sign-in: "+e))
			return
		}
		sid, err := a.Complete(r.Context(), q.Get("state"), q.Get("code"))
		if err != nil {
			problem(w, http.StatusForbidden, err)
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
		writeJSON(w, map[string]any{
			"signedIn": ok,
			"email":    who.Email,
			// The page renders one of two consoles off this. An operator gets
			// the whole relay; everybody else gets their own space, which is
			// the same shape with one row in it.
			"operator": who.Operator,
			"signup":   string(a.cfg.Signup),
		})
	})

	// ---- anybody signed in: their own space --------------------------------

	mux.Handle("GET /admin/v1/my/accounts", a.signedIn(func(w http.ResponseWriter, r *http.Request, who Signed) {
		list, err := admin.AccountsOf(r.Context(), who.UserID)
		if err != nil {
			problem(w, http.StatusInternalServerError, err)
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
			problem(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, map[string]any{"invite": token, "hours": 24})
	}))

	// ---- the operator: the whole relay -------------------------------------

	mux.Handle("GET /admin/v1/users", a.operator(func(w http.ResponseWriter, r *http.Request, _ Signed) {
		list, err := admin.Users(r.Context())
		if err != nil {
			problem(w, http.StatusInternalServerError, err)
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
			problem(w, http.StatusInternalServerError, err)
			return
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
			problem(w, http.StatusInternalServerError, err)
			return
		}
		// The token is returned ONCE and never stored anywhere this page can
		// read again, which is why the UI copies it immediately and says so.
		writeJSON(w, map[string]any{"invite": token, "hours": hours})
	}))

	mux.Handle("GET /admin/v1/accounts", a.operator(func(w http.ResponseWriter, r *http.Request, _ Signed) {
		list, err := admin.Accounts(r.Context())
		if err != nil {
			problem(w, http.StatusInternalServerError, err)
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
			problem(w, http.StatusInternalServerError, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	mux.Handle("DELETE /admin/v1/accounts/{id}", a.operator(func(w http.ResponseWriter, r *http.Request, _ Signed) {
		if err := admin.DeleteAccount(r.Context(), r.PathValue("id")); err != nil {
			problem(w, http.StatusInternalServerError, err)
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

func problem(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

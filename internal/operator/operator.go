// Package operator is the sign-in for the person who RUNS this relay.
//
// ---------------------------------------------------------------------------
// WHAT THIS IS NOT
// ---------------------------------------------------------------------------
//
// It is not a way to manage devices from a browser, and that is not a gap to
// fill later. Adding or removing a device is a signed entry in a hash-chained
// log, signed by a key that exists only on the account's own machines. A
// browser session holds no such key. For a web page to add a device, this
// server would have to hold key material — which ends the end-to-end
// encryption that is the entire product. So the operator portal can see how
// many devices an account has and how many bytes it uses, and it cannot touch
// either.
//
// What it CAN do is everything on the availability and identity plane, which
// is exactly what the threat model already concedes to the server: mint an
// invite, list accounts, set a quota, delete an account. Every one of those is
// something a person with SSH to this box can already do; the portal removes
// the SSH, not a boundary.
//
// ---------------------------------------------------------------------------
// WHY THERE IS NO JWT VERIFICATION HERE
// ---------------------------------------------------------------------------
//
// The obvious OIDC implementation validates the ID token: fetch the JWKS,
// pick the key by `kid`, check `alg`, verify the signature, check `iss`,
// `aud`, `exp`, `nonce`. Every one of those is a step with a known way to get
// it wrong, and `alg: none` and algorithm-confusion are in that list.
//
// This does the authorization-code exchange and then asks the provider's
// UserInfo endpoint who the token belongs to, over TLS, with the access token.
// The provider answers as an authenticated party rather than through a
// signature this code has to check itself. It is a normal OIDC pattern, it
// needs no key handling, and the failure modes are HTTP failures rather than
// cryptographic ones.
//
// The cost is one extra round trip per sign-in, on a page used by one person
// occasionally.
package operator

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// OperatorKey is the instance row holding who claimed this relay.
//
// Stored as "<issuer>\x00<subject>". Both halves, because a subject is only
// unique within its issuer — and an operator who switches providers should
// have to re-claim rather than silently match somebody else's identifier.
const OperatorKey = "operator_identity"

// Store is what this package needs from the database.
type Store interface {
	InstanceValue(ctx context.Context, key string) (string, time.Time, error)
	SetInstanceValue(ctx context.Context, key, value string) error
}

// Config is the provider, as the operator configured it.
//
// Google is not special: it is `https://accounts.google.com` in Issuer. Any
// provider with OIDC discovery works, which is the point — a relay somebody
// runs for their own team should be able to sit behind whatever that team
// already uses.
type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	// The public origin this relay answers on, for building the redirect URI.
	BaseURL string
}

// Enabled reports whether an operator portal should exist at all.
//
// UNCONFIGURED MEANS ABSENT, not open. A relay with no provider configured
// serves no admin routes: `addy invite` over SSH still works, and a portal
// that authenticated nobody would be worse than no portal.
func (c Config) Enabled() bool {
	return c.Issuer != "" && c.ClientID != "" && c.ClientSecret != "" && c.BaseURL != ""
}

type discovery struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
}

type identity struct {
	Subject string `json:"sub"`
	Email   string `json:"email"`
	Name    string `json:"name"`
}

// Auth holds the sign-in state for one running relay.
type Auth struct {
	cfg   Config
	store Store
	now   func() time.Time
	http  *http.Client

	mu       sync.Mutex
	found    *discovery
	pending  map[string]pendingLogin // state -> what it was for
	sessions map[string]session
}

type pendingLogin struct {
	verifier string
	at       time.Time
}

type session struct {
	subject string
	email   string
	expires time.Time
}

// Sessions live in memory ON PURPOSE. A restart signs the operator out, which
// for an administrative surface is the correct behaviour rather than a cost:
// the box was restarted and whoever is holding a cookie should prove who they
// are again.
const sessionTTL = 8 * time.Hour

// A login that is not completed promptly is one that was abandoned, or one
// somebody is holding open.
const pendingTTL = 10 * time.Minute

func New(cfg Config, store Store) *Auth {
	return &Auth{
		cfg:      cfg,
		store:    store,
		now:      time.Now,
		http:     &http.Client{Timeout: 15 * time.Second},
		pending:  map[string]pendingLogin{},
		sessions: map[string]session{},
	}
}

func (a *Auth) discover(ctx context.Context) (*discovery, error) {
	a.mu.Lock()
	if a.found != nil {
		d := a.found
		a.mu.Unlock()
		return d, nil
	}
	a.mu.Unlock()

	u := strings.TrimSuffix(a.cfg.Issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("operator: reaching %s: %w", a.cfg.Issuer, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("operator: %s answered %d to discovery", a.cfg.Issuer, resp.StatusCode)
	}
	var d discovery
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return nil, fmt.Errorf("operator: reading discovery from %s: %w", a.cfg.Issuer, err)
	}
	if d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" || d.UserinfoEndpoint == "" {
		// Refused rather than half-configured. A provider without a UserInfo
		// endpoint cannot be used by this implementation, and finding that out
		// at sign-in is better than at the callback.
		return nil, errors.New("operator: that issuer does not advertise the endpoints this needs")
	}

	a.mu.Lock()
	a.found = &d
	a.mu.Unlock()
	return &d, nil
}

func (a *Auth) redirectURI() string {
	return strings.TrimSuffix(a.cfg.BaseURL, "/") + "/admin/callback"
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Start begins a sign-in and returns where to send the browser.
func (a *Auth) Start(ctx context.Context) (string, error) {
	d, err := a.discover(ctx)
	if err != nil {
		return "", err
	}
	state, err := randomToken()
	if err != nil {
		return "", err
	}
	// PKCE, even though this is a confidential client with a secret. It costs
	// two lines and it removes the whole class of attack where an intercepted
	// authorization code is redeemed by somebody else.
	verifier, err := randomToken()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	a.mu.Lock()
	a.sweepLocked()
	a.pending[state] = pendingLogin{verifier: verifier, at: a.now()}
	a.mu.Unlock()

	q := url.Values{}
	q.Set("client_id", a.cfg.ClientID)
	q.Set("response_type", "code")
	q.Set("scope", "openid email profile")
	q.Set("redirect_uri", a.redirectURI())
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	return d.AuthorizationEndpoint + "?" + q.Encode(), nil
}

// Complete finishes a sign-in and returns the session cookie value.
func (a *Auth) Complete(ctx context.Context, state, code string) (string, error) {
	a.mu.Lock()
	a.sweepLocked()
	held, ok := a.pending[state]
	delete(a.pending, state)
	a.mu.Unlock()
	if !ok {
		// Consumed on use, so a replayed callback finds nothing. Reported as a
		// stale sign-in rather than as a failure, because the ordinary cause
		// is a back button.
		return "", errors.New("that sign-in is no longer in progress; start again")
	}

	d, err := a.discover(ctx)
	if err != nil {
		return "", err
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", a.redirectURI())
	form.Set("client_id", a.cfg.ClientID)
	form.Set("client_secret", a.cfg.ClientSecret)
	form.Set("code_verifier", held.verifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := a.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("operator: exchanging the code: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("operator: the provider refused the code (%d)", resp.StatusCode)
	}
	var token struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil || token.AccessToken == "" {
		return "", errors.New("operator: the provider returned no access token")
	}

	who, err := a.userinfo(ctx, d.UserinfoEndpoint, token.AccessToken)
	if err != nil {
		return "", err
	}
	if who.Subject == "" {
		return "", errors.New("operator: the provider returned no subject")
	}

	if err := a.claimOrCheck(ctx, who.Subject); err != nil {
		return "", err
	}

	sid, err := randomToken()
	if err != nil {
		return "", err
	}
	a.mu.Lock()
	a.sessions[key(sid)] = session{subject: who.Subject, email: who.Email, expires: a.now().Add(sessionTTL)}
	a.mu.Unlock()
	return sid, nil
}

func (a *Auth) userinfo(ctx context.Context, endpoint, accessToken string) (*identity, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := a.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("operator: asking who that token belongs to: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("operator: the provider would not identify the token (%d)", resp.StatusCode)
	}
	var who identity
	if err := json.NewDecoder(resp.Body).Decode(&who); err != nil {
		return nil, fmt.Errorf("operator: reading the identity: %w", err)
	}
	return &who, nil
}

// claimOrCheck is the whole access-control decision.
//
// FIRST IN CLAIMS IT, and everybody after has to be them. That is how a
// self-hosted box is normally taken over by its owner, and the alternative —
// anyone with an account at the configured provider being an admin — is not a
// decision anybody would make on purpose. Configuring Google without this
// would make every Google account in the world an operator of the relay.
func (a *Auth) claimOrCheck(ctx context.Context, subject string) error {
	want := a.cfg.Issuer + "\x00" + subject

	held, _, err := a.store.InstanceValue(ctx, OperatorKey)
	if err != nil {
		return fmt.Errorf("operator: reading the claim: %w", err)
	}
	if held == "" {
		if err := a.store.SetInstanceValue(ctx, OperatorKey, want); err != nil {
			return fmt.Errorf("operator: claiming this relay: %w", err)
		}
		return nil
	}
	// Constant time, because this compares an identifier an attacker can vary
	// against one they are trying to learn.
	if subtle.ConstantTimeCompare([]byte(held), []byte(want)) != 1 {
		return errors.New("this relay already has an operator, and it is not this account")
	}
	return nil
}

// Session returns who is signed in, or false.
func (a *Auth) Session(sid string) (string, bool) {
	if sid == "" {
		return "", false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sweepLocked()
	s, ok := a.sessions[key(sid)]
	if !ok || a.now().After(s.expires) {
		return "", false
	}
	return s.email, true
}

// End signs one session out.
func (a *Auth) End(sid string) {
	a.mu.Lock()
	delete(a.sessions, key(sid))
	a.mu.Unlock()
}

// key hashes a session id before it is used as a map key, so a heap dump does
// not hand out live sessions. The same discipline the API's bearer tokens use.
func key(sid string) string {
	sum := sha256.Sum256([]byte("addy-operator-session-v1\x00" + sid))
	return string(sum[:])
}

func (a *Auth) sweepLocked() {
	now := a.now()
	for k, v := range a.pending {
		if now.Sub(v.at) > pendingTTL {
			delete(a.pending, k)
		}
	}
	for k, v := range a.sessions {
		if now.After(v.expires) {
			delete(a.sessions, k)
		}
	}
}

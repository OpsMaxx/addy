// Package overlay mints headscale pre-authentication keys, one per device,
// from the roster.
//
// WHAT THIS IS NOT. It is not a VPN and does not carry a packet. Tailscale's
// client already exists and OpsMaxx already drives it; headscale already
// coordinates. The missing piece was always the join: somebody has to decide
// which machines belong, and doing that by hand means copying a pre-auth key
// out of a terminal into another machine, which is a credential travelling
// through a clipboard.
//
// addy already knows which machines belong. That is the roster -- signed,
// hash-chained, verified from genesis by every device. So the join becomes:
// prove you are a device on this account, and get a key for yourself alone.
//
// ONE KEY PER DEVICE, SINGLE USE, SHORT LIVED. A reusable key is a key that
// leaks once and admits anyone forever; the roster is what makes minting a
// fresh one per device cheap enough that reusable has no excuse.
package overlay

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// KeyTTL is how long a minted key is good for.
//
// Minutes, not days. The key is handed to a device that is about to use it --
// the user pressed a button and the client is waiting -- so anything longer is
// a window with no purpose. A device that fails to join in ten minutes asks
// again, which costs one API call.
const KeyTTL = 10 * time.Minute

// Config is what an operator supplies to connect addy to headscale.
type Config struct {
	// BaseURL of headscale's API. Loopback when the M5a wizard deployed it,
	// which is the case this is written for.
	BaseURL string
	// APIKey for headscale. This is a powerful credential: it can create and
	// delete nodes, users and keys across the whole coordination server.
	APIKey string
	// User headscale should own the nodes. One user for the account keeps the
	// node list readable; per-device users would make headscale's own UI
	// unusable at any size.
	User string
	// HTTP lets a test substitute a transport. Nil means a client with a short
	// timeout -- headscale is on loopback and a call that hangs blocks a user
	// who is watching a spinner.
	HTTP *http.Client
}

// Minter talks to headscale.
type Minter struct {
	cfg  Config
	http *http.Client
}

func New(cfg Config) (*Minter, error) {
	if cfg.BaseURL == "" || cfg.APIKey == "" {
		return nil, errors.New("overlay: headscale needs a base URL and an API key")
	}
	if cfg.User == "" {
		cfg.User = "addy"
	}
	client := cfg.HTTP
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &Minter{cfg: cfg, http: client}, nil
}

// PreauthKey is what a device is given.
type PreauthKey struct {
	Key       string    `json:"key"`
	ExpiresAt time.Time `json:"expiresAt"`
	// ControlURL is what the client points at. Returned with the key because a
	// key without it is half an answer, and the two have to agree.
	ControlURL string `json:"controlUrl"`
}

// Mint issues a single-use key for one device.
//
// `device` is the device's signing key in hex, and it becomes a TAG on the
// node so that an operator looking at headscale's node list can match a
// machine to a roster entry. That matters at the only moment it ever does: a
// device is revoked in addy, and somebody has to find the corresponding node
// and remove it.
func (m *Minter) Mint(ctx context.Context, device []byte, controlURL string) (*PreauthKey, error) {
	if len(device) == 0 {
		return nil, errors.New("overlay: minting a key for no device")
	}
	body, err := json.Marshal(map[string]any{
		"user":       m.cfg.User,
		"reusable":   false,
		"ephemeral":  false,
		"expiration": time.Now().Add(KeyTTL).UTC().Format(time.RFC3339),
		// `tag:` is headscale's own namespace for ACL tags and it requires the
		// prefix -- it rejects anything without it, which is the sort of thing
		// discovered at deployment rather than in review.
		"aclTags": []string{"tag:addy-" + shortHex(device)},
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(m.cfg.BaseURL, "/")+"/api/v1/preauthkey", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+m.cfg.APIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("overlay: reaching headscale: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// The message is deliberately about the OPERATOR's configuration
		// rather than the user's request: a 401 here means addy's API key is
		// wrong, which is nothing the person pressing the button can fix and
		// everything the person who deployed headscale can.
		return nil, fmt.Errorf(
			"overlay: headscale answered %s. addy's API key or user may be wrong; "+
				"check `headscale users list` and the key addy was given", resp.Status)
	}

	var out struct {
		PreAuthKey struct {
			Key        string `json:"key"`
			Expiration string `json:"expiration"`
		} `json:"preAuthKey"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("overlay: headscale's answer did not parse: %w", err)
	}
	if out.PreAuthKey.Key == "" {
		return nil, errors.New("overlay: headscale returned no key")
	}

	expires, err := time.Parse(time.RFC3339, out.PreAuthKey.Expiration)
	if err != nil {
		// Not fatal. The key works; we simply cannot tell the user when it
		// stops, and guessing would be worse than saying nothing.
		expires = time.Time{}
	}

	return &PreauthKey{
		Key:        out.PreAuthKey.Key,
		ExpiresAt:  expires,
		ControlURL: controlURL,
	}, nil
}

// shortHex is the device key, truncated for a label.
//
// A tag is something an operator reads in a node list; 64 characters of hex
// there helps nobody. Truncated SAFELY: the obvious `[:16]` panics on a key
// shorter than eight bytes, and a panic reachable from a request handler is a
// panic that takes the process down whatever the handler's recover does about
// that one request. A real device key is 32 bytes and would never hit it,
// which is exactly why it would have survived review.
func shortHex(b []byte) string {
	encoded := hex.EncodeToString(b)
	if len(encoded) <= 16 {
		return encoded
	}
	return encoded[:16]
}

package api

import (
	"encoding/hex"
	"errors"
	"net/http"
)

// TurnMinter issues short-lived relay credentials.
//
// An interface, not the relay type, for the reason the whole transport seam
// exists: an operator may be pointing devices at coturn, or at nothing, and
// the API should not import a TURN implementation to say so. It also means a
// test can assert what a device is told without binding a UDP port.
type TurnMinter interface {
	// Mint issues a credential for one device, named by its hex signing key.
	Mint(device string) any
}

// turnConfig is what a device is told about relaying.
//
// Deliberately a whole answer rather than a credential: "there is no relay" is
// a legitimate configuration -- an operator who wants no relaying, or who has
// not given a public IP -- and a device needs to be told that clearly rather
// than by a 404 it has to interpret.
type turnConfig struct {
	// "embedded", "external" or "none".
	Mode string `json:"mode"`
	// Set for "external": the URL to use, with no credential, because the
	// operator's own relay has its own arrangements.
	URL string `json:"url,omitempty"`
	// Set for "embedded".
	Credential any `json:"credential,omitempty"`
}

// turn tells the authenticated device how to relay, if at all.
//
// A CREDENTIAL PER DEVICE, per request, short-lived. Relaying is somebody
// else's bandwidth: a long-lived shared secret handed to every device is an
// open relay one leaked config file away, and an abuse complaint with the
// operator's name on it.
func (s *Server) turn(w http.ResponseWriter, r *http.Request, a authedRequest) {
	switch {
	case s.TurnExternal != "":
		s.ok(w, turnConfig{Mode: "external", URL: s.TurnExternal})
	case s.Turn != nil:
		s.ok(w, turnConfig{
			Mode:       "embedded",
			Credential: s.Turn.Mint(hex.EncodeToString(a.Device)),
		})
	default:
		// 200 with "none", not 404. A device that cannot relay still needs to
		// know that, so it can tell the user "this pair of networks needs a
		// relay and this box does not run one" instead of failing to connect
		// for no stated reason.
		s.ok(w, turnConfig{Mode: "none"})
	}
}

var errNoTurn = errors.New("this instance runs no relay")

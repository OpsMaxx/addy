package api

import (
	"context"
	"errors"
	"net/http"
)

// The overlay join, in one call.
//
// A DEVICE ON THE ROSTER IS A DEVICE ON THE OVERLAY, and this endpoint is the
// whole of that sentence. Authentication here is the same authentication as
// everywhere else -- a session plus a signed request authorization -- so a
// device that can ask is by construction a device the account owner added and
// has not revoked: login reads the roster, a key it does not name never gets
// past recoveryRoute, and a revoke ends the device's sessions (members.go).
// That sentence was here before any of it was true.
//
// That is the feature. Without it, joining a machine means copying a pre-auth
// key out of one terminal into another, which is a credential travelling
// through a clipboard, and it is why "one button" was the requirement rather
// than "document the steps".

// OverlayMinter is the half that talks to headscale.
//
// An interface, and `any` for the result, so that this package does not import
// one for a service most instances will never configure -- and so a test can
// assert what a device is handed without standing up a headscale.
type OverlayMinter interface {
	Mint(ctx context.Context, device []byte, controlURL string) (any, error)
}

// overlayJoin mints a single-use key for the calling device.
func (s *Server) overlayJoin(w http.ResponseWriter, r *http.Request, a authedRequest) {
	if s.Overlay == nil {
		// 501, not 404: the route exists on every instance and the answer is
		// about this instance's configuration. A client that saw 404 would
		// conclude the server is too old.
		s.fail(w, http.StatusNotImplemented,
			errors.New("this relay has no overlay configured; the operator deploys headscale with `addy service install headscale` and points addy at it"))
		return
	}

	key, err := s.Overlay.Mint(r.Context(), a.Device, s.OverlayControlURL)
	if err != nil {
		// 502: the failure is between addy and headscale, and a client that
		// treated it as its own problem would retry forever.
		s.fail(w, http.StatusBadGateway, err)
		return
	}
	s.ok(w, key)
}

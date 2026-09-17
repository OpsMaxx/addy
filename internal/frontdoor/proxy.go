package frontdoor

import (
	"net/http"
	"net/http/httputil"
	"net/url"
)

// proxyTo returns the reverse proxy for a loopback backend, building it once.
//
// Vaultwarden and headscale both generate absolute URLs. Without the forwarded
// headers below they emit http:// links from behind an https:// front door, and
// the symptom is a login flow that redirects a browser out of TLS -- which
// looks like a certificate problem and is not.
//
// Websocket upgrades pass through untouched: httputil.ReverseProxy has handled
// them since Go 1.12, so headscale's DERP and stream endpoints need no library
// and no special case.
func (d *Door) proxyTo(backend string) http.Handler {
	if p, ok := d.proxies.Load(backend); ok {
		return p.(*httputil.ReverseProxy)
	}

	target := &url.URL{Scheme: "http", Host: backend}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			// SetXForwarded sets For, Host and Proto -- but Proto from the
			// INBOUND request, which for a request that arrived on :80 is
			// "http" even though the client is being served behind TLS
			// elsewhere. Set it explicitly after.
			r.SetXForwarded()
			r.Out.Header.Set("X-Forwarded-Proto", "https")
			// Preserve the hostname the client asked for. A backend doing its
			// own vhosting -- which is why headscale is proxied rather than
			// terminated -- needs the original, not the loopback address.
			r.Out.Host = r.In.Host
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			d.Log.Warn("backend is unreachable", "backend", backend, "host", r.Host, "err", err)
			// 502 and not 500: the failure is behind us, and saying so is the
			// difference between an operator checking addy and checking the
			// service that is actually down.
			http.Error(w, "the service behind this hostname is not responding", http.StatusBadGateway)
		},
	}

	actual, _ := d.proxies.LoadOrStore(backend, proxy)
	return actual.(*httputil.ReverseProxy)
}

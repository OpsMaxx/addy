package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/opsmaxx/addy/internal/protocol"
)

// /v1/meta must answer WITH THE PORTAL OFF.
//
// It used to be mounted on the portal's handler, which is a 404 when -ui is
// off -- and the portal is headless by default, because it is a web surface on
// a box whose whole pitch is that it holds nothing worth attacking. So on a
// default install the one endpoint the container healthcheck and `addy
// selftest` both fetch answered 404: the healthcheck failed forever, and the
// selftest reported "something is listening and it is not addy" about addy.
//
// Found by running the selftest against a real instance. Nothing in the unit
// tests could see it, because every one of them built a portal -- the
// configuration that broke was the only one nothing covered.
func TestMetaAnswersAndExposesNothingElse(t *testing.T) {
	rec := httptest.NewRecorder()
	metaHandler(Config{Version: "1.2.3", BuildSha: "abcdef"}).
		ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/meta", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("/v1/meta answered %d; the healthcheck fetches this", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("meta is not JSON: %s", rec.Body.String())
	}
	if body["version"] != "1.2.3" || body["build"] != "abcdef" {
		t.Fatalf("meta is %s", rec.Body.String())
	}
	if body["protocol"] != protocol.ProtocolVersion {
		t.Errorf("meta names protocol %q, want %q", body["protocol"], protocol.ProtocolVersion)
	}
	for key := range body {
		if key != "version" && key != "build" && key != "protocol" {
			t.Errorf("meta exposes %q", key)
		}
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control is %q; a cached healthcheck answer is not a healthcheck", cc)
	}
}

// The mounting, which is the half the handler test cannot see: a correct
// handler on the wrong mux is exactly the bug that shipped.
func TestMetaIsNotMountedOnThePortal(t *testing.T) {
	b, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatalf("reading server.go: %v", err)
	}
	src := string(b)
	if strings.Contains(src, `mux.Handle("/v1/meta", pages)`) {
		t.Fatal(`/v1/meta is mounted on the portal handler again; it 404s on every default install`)
	}
	if !strings.Contains(src, `mux.Handle("/v1/meta", metaHandler(cfg))`) {
		t.Fatal("/v1/meta is no longer mounted unconditionally on the mux")
	}
}

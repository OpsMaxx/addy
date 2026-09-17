package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// Selftest proves a running instance actually works, rather than that its
// process started.
//
// The distinction is the whole point. A relay that is up and cannot relay is
// the worst first impression the product can make, and "the container is
// running" is exactly the evidence that produces it.
//
// quick is what the container healthcheck runs every thirty seconds: it checks
// the instance is answering over its own TLS and stops there. The full run adds
// the checks that need more than one round trip.
func Selftest(ctx context.Context, target string, quick bool) error {
	if target == "" {
		target = os.Getenv("ADDY_DOMAIN")
	}
	if target == "" {
		return errors.New("selftest needs a target: pass -target, or set ADDY_DOMAIN")
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	meta, err := fetchMeta(ctx, target)
	if err != nil {
		return err
	}
	fmt.Printf("  %s is answering: addy %s (%s)\n", target, meta.Version, meta.Build)

	if quick {
		return nil
	}

	// What the full run will add as each milestone lands: a pair/sync/revoke/
	// recover cycle against this instance, and a TURN check that proves a
	// packet is RELAYED rather than that the daemon started. Both need
	// machinery that does not exist yet, and a selftest that claims to have
	// checked something it did not is worse than one that says what it covers.
	fmt.Println("  (the pairing, sync and TURN relay checks arrive with the milestones that build them)")
	return nil
}

type meta struct {
	Version string `json:"version"`
	Build   string `json:"build"`
}

func fetchMeta(ctx context.Context, target string) (meta, error) {
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			// A self-signed development certificate must not make the
			// healthcheck fail, and this request goes to the instance's own
			// loopback. What is being proved here is that the process answers
			// over TLS at all -- the certificate's trustworthiness is
			// preflight's job, and it uses a real CA to answer it.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	url := "https://" + target + "/v1/meta"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return meta{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return meta{}, fmt.Errorf(`%s is not answering over TLS: %w

The relay is not serving. Check its logs; if it has only just started, a first
boot includes a real certificate order and is not instant`, target, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return meta{}, fmt.Errorf(`%s answered %s rather than 200

Something is listening and it is not addy, or addy has no route for this
hostname -- which it refuses rather than serving somebody else's name`,
			url, resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if err != nil {
		return meta{}, fmt.Errorf("reading %s: %w", url, err)
	}
	var m meta
	if err := json.Unmarshal(body, &m); err != nil {
		return meta{}, fmt.Errorf("%s did not return addy's own metadata: %w", url, err)
	}
	if m.Version == "" {
		return meta{}, fmt.Errorf("%s answered, but not with an addy version; something else is on this hostname", url)
	}
	return m, nil
}

// Package identity generates and holds a device's cryptographic identity.
//
// A DEVICE'S IDENTITY IS ITS FRESHLY GENERATED PUBLIC KEY, and nothing else.
// Nothing is read from the host to produce it: no hostname, no OS username, no
// MAC address, no disk or board serial, no machine-id, no platform advertising
// identifier. The keypair comes from the CSPRNG at first pairing and that is
// the whole of it.
//
// This is enforced rather than intended: identity_test.go asserts that no file
// in this package imports "os", so a later helpful addition of "let's include
// the hostname so the name is friendlier" fails the build instead of silently
// correlating a person's relay identity with their hardware.
package identity

import (
	"crypto/rand"
	_ "embed"
	"fmt"
	"math/big"
	"strings"
)

// The wordlists are DATA AND THEY ARE SHARED. The relay generates a device's
// name in Go and the OpsMaxx client generates it in TypeScript, and the two
// must agree -- a device that is quiet-otter-41 in the app and something else
// in the portal is worse than no name at all, because the name exists so that a
// person can recognise their own machine in a revoke dialog under stress.
//
//go:embed wordlists/adjectives.txt
var adjectivesRaw string

//go:embed wordlists/nouns.txt
var nounsRaw string

var (
	adjectives = lines(adjectivesRaw)
	nouns      = lines(nounsRaw)
)

func lines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// Pseudonym returns a fresh device name like "quiet-otter-41".
//
// GENERATED, NOT OBSERVED -- and generated to be MEMORABLE, because a name
// nobody can hold in their head is a machine id with extra steps, and the whole
// point is that a person has to recognise their own device in a revoke dialog
// under stress.
//
// The number is two digits with a leading zero, so every name is the same
// shape and the same length class. A name that is sometimes "brave-pylon-7" and
// sometimes "brave-pylon-70" is harder to compare at a glance, and comparing at
// a glance is the entire job.
//
// It is not unique and does not try to be. Uniqueness lives in the public key;
// this is a label. Two devices that draw the same name are a cosmetic problem
// the user solves by renaming one, and the renaming is local -- if someone
// renames a device to something identifying, that is their business, which is
// exactly why the label is encrypted rather than sent in the clear.
func Pseudonym() (string, error) {
	adj, err := pick(adjectives)
	if err != nil {
		return "", err
	}
	noun, err := pick(nouns)
	if err != nil {
		return "", err
	}
	n, err := rand.Int(rand.Reader, big.NewInt(100))
	if err != nil {
		return "", fmt.Errorf("generating a device name: %w", err)
	}
	return fmt.Sprintf("%s-%s-%02d", adj, noun, n.Int64()), nil
}

// pick chooses uniformly using crypto/rand.
//
// crypto/rand and not math/rand, even though this is "just a label": a
// predictable device name is a predictable thing to look for, and the cost of
// getting it from the same source as everything else here is nothing.
func pick(list []string) (string, error) {
	if len(list) == 0 {
		return "", fmt.Errorf("a wordlist is empty; the embedded data did not load")
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(list))))
	if err != nil {
		return "", fmt.Errorf("choosing a word: %w", err)
	}
	return list[n.Int64()], nil
}

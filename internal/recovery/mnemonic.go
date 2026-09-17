// Package recovery is the recovery phrase: generating it, checking what a human
// typed, and helping them type it.
//
// WHAT THE PHRASE ACTUALLY IS, said here because everything in this package
// follows from it: a BEARER TOKEN FOR THE WHOLE ESTATE MINUS THE VAULT.
// Unhardened, un-rate-limited, usable by anyone holding it from anywhere.
// Calling it a "recovery phrase" invites the mental model of an
// account-recovery email, which is the wrong one and leads people to store it
// accordingly.
//
// addy has no password reset, no email verification and no account recovery,
// because it has no account in the usual sense -- it has a signing key it was
// handed once. This is the only backup that exists.
package recovery

import (
	"errors"
	"fmt"
	"strings"

	bip39 "github.com/blinklabs-io/go-bip39"
)

// TWELVE WORDS, NOT TWENTY-FOUR, and this is a decision rather than a default.
//
// Twenty-four words is 256 bits of entropy feeding X25519 and ChaCha20-Poly1305,
// which top out at 128-bit security. The extra twelve words buy nothing and cost
// transcription errors and abandonment -- and abandonment is the real failure
// here, because a phrase nobody wrote down is a phrase nobody has.
const (
	EntropyBits = 128
	WordCount   = 12
)

// New generates a fresh recovery phrase.
func New() (string, error) {
	entropy, err := bip39.NewEntropy(EntropyBits)
	if err != nil {
		return "", fmt.Errorf("recovery: generating entropy: %w", err)
	}
	phrase, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", fmt.Errorf("recovery: generating a phrase: %w", err)
	}
	return phrase, nil
}

// Entropy recovers the 128 bits a phrase encodes. This is what the key
// hierarchy is derived from; the phrase itself is never used as key material
// directly.
func Entropy(phrase string) ([]byte, error) {
	if err := Validate(phrase); err != nil {
		return nil, err
	}
	e, err := bip39.EntropyFromMnemonic(Normalise(phrase))
	if err != nil {
		return nil, fmt.Errorf("recovery: %w", err)
	}
	return e, nil
}

// NO TWENTY-FIFTH WORD.
//
// BIP39 allows an optional passphrase that changes the derived seed. addy does
// not offer one, deliberately: a second secret protecting the backup of the
// first secret is how people lock themselves out. The phrase is already the
// thing with no second factor, and adding one that is also written on nothing
// makes the failure mode worse rather than better.
const noPassphrase = ""

// Seed derives the BIP39 seed. The key hierarchy takes it from here.
func Seed(phrase string) ([]byte, error) {
	if err := Validate(phrase); err != nil {
		return nil, err
	}
	return bip39.NewSeed(Normalise(phrase), noPassphrase), nil
}

// Normalise is what a human's typing becomes before anything looks at it.
//
// People paste with newlines and double spaces, their phone capitalises the
// first word, and some write the numbered list they were shown. None of that is
// a wrong phrase, and a recovery flow that rejects a correctly-transcribed
// phrase on whitespace is a recovery flow that fails at the one moment it
// exists for.
func Normalise(phrase string) string {
	return strings.Join(strings.Fields(strings.ToLower(phrase)), " ")
}

var (
	ErrWrongLength = errors.New("a recovery phrase is twelve words")
	ErrNotInList   = errors.New("that is not a BIP39 word")
	ErrChecksum    = errors.New("those are all real words, but not in that order")
)

// UnknownWord names a word that is not in the list, and where it was.
type UnknownWord struct {
	Index int // zero-based
	Word  string
}

func (u UnknownWord) Error() string {
	return fmt.Sprintf("word %d (%q) is not a BIP39 word", u.Index+1, u.Word)
}

func (u UnknownWord) Unwrap() error { return ErrNotInList }

// Validate checks a phrase and says WHICH WORD is wrong when it can.
//
// This is the whole reason this function is not just bip39.IsMnemonicValid.
// BIP39's checksum only ever says "this is wrong" and never "word 17 is wrong",
// so a user who mistyped one word is told their entire phrase is invalid and
// has no way to find the error except to retype all twelve and hope. Per-word
// validation turns that into "word 7 is not a word", which is actionable.
//
// The checksum failure is worth distinguishing too, and its message says what
// it means: every word is real, so this is a transposition or a substitution of
// one real word for another, not a typo.
func Validate(phrase string) error {
	words := strings.Fields(Normalise(phrase))
	if len(words) != WordCount {
		return fmt.Errorf("%w, and this has %d", ErrWrongLength, len(words))
	}
	for i, w := range words {
		if _, ok := bip39.GetWordIndex(w); !ok {
			return UnknownWord{Index: i, Word: w}
		}
	}
	if !bip39.IsMnemonicValid(strings.Join(words, " ")) {
		return ErrChecksum
	}
	return nil
}

// Complete returns the BIP39 words beginning with prefix.
//
// Autocomplete is not a nicety here. BIP39 words are chosen so the first four
// letters are unique, which is a property that only helps someone if the
// software uses it -- and someone transcribing twelve words off a printed card
// under stress is exactly who needs it used.
//
// A single result means the word is determined, and the caller should say so
// rather than making the user type the rest.
func Complete(prefix string) []string {
	prefix = strings.ToLower(strings.TrimSpace(prefix))
	if prefix == "" {
		return nil
	}
	var out []string
	for _, w := range bip39.GetWordList() {
		if strings.HasPrefix(w, prefix) {
			out = append(out, w)
		}
	}
	return out
}

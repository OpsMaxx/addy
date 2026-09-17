package recovery

import (
	"errors"
	"strings"
	"testing"

	bip39 "github.com/blinklabs-io/go-bip39"
)

func TestAFreshPhraseIsTwelveValidWords(t *testing.T) {
	for i := 0; i < 50; i++ {
		phrase, err := New()
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		words := strings.Fields(phrase)
		if len(words) != WordCount {
			t.Fatalf("phrase has %d words, want %d: %q", len(words), WordCount, phrase)
		}
		if err := Validate(phrase); err != nil {
			t.Fatalf("a freshly generated phrase did not validate: %v", err)
		}
	}
}

func TestTwoPhrasesAreNeverTheSame(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 200; i++ {
		p, err := New()
		if err != nil {
			t.Fatal(err)
		}
		if seen[p] {
			t.Fatalf("New returned a repeat: %q", p)
		}
		seen[p] = true
	}
}

// The whole reason Validate is not just IsMnemonicValid. BIP39's checksum only
// ever says "this is wrong", never "word 7 is wrong", so a user who mistyped
// one word is told their entire phrase is invalid with no way to find the error
// but to retype all twelve and hope.
func TestAMistypedWordIsNamedAndNumbered(t *testing.T) {
	phrase, err := New()
	if err != nil {
		t.Fatal(err)
	}
	words := strings.Fields(phrase)
	words[6] = "zzzznotaword"

	err = Validate(strings.Join(words, " "))
	if err == nil {
		t.Fatal("a phrase with a nonsense word validated")
	}
	if !errors.Is(err, ErrNotInList) {
		t.Fatalf("Validate = %v, want it to unwrap to ErrNotInList", err)
	}
	var u UnknownWord
	if !errors.As(err, &u) {
		t.Fatalf("Validate = %v, want an UnknownWord naming the position", err)
	}
	if u.Index != 6 {
		t.Errorf("UnknownWord.Index = %d, want 6", u.Index)
	}
	// The message is the deliverable: it has to be actionable by someone
	// holding a printed card.
	if !strings.Contains(u.Error(), "word 7") {
		t.Errorf("message %q does not say which word, one-based", u.Error())
	}
}

// Every word real but the order wrong is a different failure from a typo, and
// it needs a different message -- "those are all real words, but not in that
// order" tells someone to look for a transposition.
func TestARealButWrongPhraseFailsTheChecksumDistinctly(t *testing.T) {
	phrase, err := New()
	if err != nil {
		t.Fatal(err)
	}
	words := strings.Fields(phrase)

	// Swap two words. Overwhelmingly likely to break the checksum while
	// leaving every word real.
	words[0], words[1] = words[1], words[0]
	swapped := strings.Join(words, " ")
	if bip39.IsMnemonicValid(swapped) {
		t.Skip("the swap happened to stay valid; nothing to assert")
	}

	err = Validate(swapped)
	if !errors.Is(err, ErrChecksum) {
		t.Fatalf("Validate = %v, want ErrChecksum", err)
	}
	if errors.Is(err, ErrNotInList) {
		t.Error("a checksum failure was reported as an unknown word")
	}
}

func TestTheWrongNumberOfWordsSaysSo(t *testing.T) {
	phrase, err := New()
	if err != nil {
		t.Fatal(err)
	}
	words := strings.Fields(phrase)

	for _, in := range []string{
		strings.Join(words[:11], " "),
		phrase + " " + words[0],
		"",
	} {
		err := Validate(in)
		if !errors.Is(err, ErrWrongLength) {
			t.Errorf("Validate(%d words) = %v, want ErrWrongLength", len(strings.Fields(in)), err)
		}
	}
}

// People paste with newlines and double spaces, and their phone capitalises the
// first word. None of that is a wrong phrase, and rejecting a correctly
// transcribed one on whitespace fails at the one moment this exists for.
func TestWhatPeopleActuallyPasteIsAccepted(t *testing.T) {
	phrase, err := New()
	if err != nil {
		t.Fatal(err)
	}
	words := strings.Fields(phrase)

	for _, in := range []string{
		phrase,
		"  " + phrase + "\n",
		strings.Join(words, "\n"),
		strings.Join(words, "  "),
		strings.ToUpper(words[0]) + " " + strings.Join(words[1:], " "),
		strings.ToUpper(phrase),
	} {
		if err := Validate(in); err != nil {
			t.Errorf("Validate(%q...) = %v, want it accepted", in[:min(24, len(in))], err)
		}
	}
}

// BIP39 words are chosen so the first four letters are unique -- a property
// that only helps someone if the software uses it, and someone transcribing
// twelve words off a card under stress is exactly who needs it used.
func TestFourLettersDetermineAWord(t *testing.T) {
	list := bip39.GetWordList()
	if len(list) != 2048 {
		t.Fatalf("the wordlist has %d entries, want 2048", len(list))
	}
	checked := 0
	for _, w := range list {
		if len(w) < 4 {
			continue
		}
		matches := Complete(w[:4])
		checked++
		if len(matches) != 1 {
			t.Errorf("Complete(%q) returned %d words, want exactly 1: %v", w[:4], len(matches), matches)
		}
	}
	if checked == 0 {
		t.Fatal("checked no words; the test is wrong, not the list")
	}
}

func TestCompleteNarrowsAsYouType(t *testing.T) {
	if got := Complete(""); got != nil {
		t.Errorf("Complete(\"\") = %v, want nothing", got)
	}
	if got := Complete("zzzz"); len(got) != 0 {
		t.Errorf("Complete(\"zzzz\") = %v, want nothing", got)
	}
	wide := Complete("ab")
	narrow := Complete("aba")
	if len(wide) < len(narrow) {
		t.Errorf("a longer prefix matched more words: %d vs %d", len(wide), len(narrow))
	}
	for _, w := range narrow {
		if !strings.HasPrefix(w, "aba") {
			t.Errorf("Complete(\"aba\") returned %q", w)
		}
	}
}

// The entropy is what the key hierarchy is built from, so it has to be stable
// and the right size.
func TestEntropyIsStableAndTheRightSize(t *testing.T) {
	phrase, err := New()
	if err != nil {
		t.Fatal(err)
	}
	e1, err := Entropy(phrase)
	if err != nil {
		t.Fatalf("Entropy: %v", err)
	}
	if len(e1)*8 != EntropyBits {
		t.Fatalf("entropy is %d bits, want %d", len(e1)*8, EntropyBits)
	}
	// The same phrase, typed messily, must give the same bytes -- otherwise a
	// user recovers onto a different account and everything is simply missing.
	e2, err := Entropy("  " + strings.ToUpper(phrase) + "\n")
	if err != nil {
		t.Fatalf("Entropy on a messy phrase: %v", err)
	}
	if string(e1) != string(e2) {
		t.Error("the same phrase typed differently produced different entropy")
	}
	if _, err := Entropy("not a phrase"); err == nil {
		t.Error("Entropy accepted nonsense")
	}
}

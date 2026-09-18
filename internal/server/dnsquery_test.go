package server

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

// The strict parser.
//
// Every case here is a reply this must refuse rather than half-read: a
// preflight that reports a partial truth sends an operator to debug DNS that
// is already correct, which is worse than one that says it could not tell.

func query(t *testing.T, name string) []byte {
	t.Helper()
	msg, err := buildQuery(name)
	if err != nil {
		t.Fatalf("buildQuery: %v", err)
	}
	return msg
}

// reply builds an answer to `q` with the given A records.
func reply(q []byte, addrs ...[4]byte) []byte {
	out := make([]byte, 12)
	copy(out, q[:2])                            // same id
	binary.BigEndian.PutUint16(out[2:], 0x8180) // response, no error
	binary.BigEndian.PutUint16(out[4:], 1)      // one question
	binary.BigEndian.PutUint16(out[6:], uint16(len(addrs)))
	out = append(out, q[12:]...) // echo the question
	for _, a := range addrs {
		out = append(out, 0xc0, 0x0c) // pointer to the question's name
		out = append(out, 0, 1, 0, 1) // A, IN
		out = append(out, 0, 0, 0, 60)
		out = append(out, 0, 4)
		out = append(out, a[:]...)
	}
	return out
}

func TestItReadsARecords(t *testing.T) {
	q := query(t, "example.com")
	got, err := parseA(q[:2], reply(q, [4]byte{93, 184, 216, 34}, [4]byte{1, 2, 3, 4}))
	if err != nil {
		t.Fatalf("parseA: %v", err)
	}
	if len(got) != 2 || got[0] != "93.184.216.34" || got[1] != "1.2.3.4" {
		t.Fatalf("parsed %v", got)
	}
}

// Not our question. A resolver does not do this; something in the middle
// might, and answering somebody else's query as though it were ours is the one
// thing that must not happen silently.
func TestItRefusesAReplyToADifferentQuery(t *testing.T) {
	q := query(t, "example.com")
	r := reply(q, [4]byte{1, 2, 3, 4})
	r[0] ^= 0xff
	if _, err := parseA(q[:2], r); err == nil || !strings.Contains(err.Error(), "different query") {
		t.Fatalf("a mismatched id gave %v", err)
	}
}

func TestItReportsNoSuchNameAsItself(t *testing.T) {
	q := query(t, "nope.example.com")
	r := reply(q)
	r[3] = (r[3] &^ 0x0f) | 3 // NXDOMAIN
	if _, err := parseA(q[:2], r); err == nil || !strings.Contains(err.Error(), "no such name") {
		t.Fatalf("NXDOMAIN gave %v", err)
	}
}

func TestItRefusesATruncatedReply(t *testing.T) {
	q := query(t, "example.com")
	full := reply(q, [4]byte{1, 2, 3, 4})
	for _, cut := range []int{0, 5, 11, len(full) - 2} {
		if _, err := parseA(q[:2], full[:cut]); err == nil {
			t.Errorf("a reply cut to %d bytes parsed anyway", cut)
		}
	}
}

// A pointer chain is how a malicious reply makes a parser spin forever. One
// pointer is followed and the name ends there; a chain cannot loop.
func TestACompressionPointerCannotLoop(t *testing.T) {
	msg := make([]byte, 20)
	msg[12], msg[13] = 0xc0, 0x0c // a pointer to itself
	done := make(chan struct{})
	go func() {
		_, _ = skipName(msg, 12)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("skipName did not return on a self-referential pointer")
	}
}

func TestItRefusesANameItCannotAskAbout(t *testing.T) {
	// An empty label, and a label past the 63-byte limit. Both are names no
	// resolver would answer, and building the query is where that is cheapest
	// to notice.
	if _, err := buildQuery(strings.Repeat("a", 64) + ".example.com"); err == nil {
		t.Error("a 64-byte label was accepted")
	}
}

func TestAnswersWithNoARecordSaySo(t *testing.T) {
	// A name that exists with only a CNAME or only AAAA. Reported as "no A
	// record" rather than as an empty success, so the caller falls through to
	// the next resolver rather than believing this one.
	q := query(t, "example.com")
	if _, err := parseA(q[:2], reply(q)); err == nil || !strings.Contains(err.Error(), "no A record") {
		t.Fatalf("an empty answer gave %v", err)
	}
}

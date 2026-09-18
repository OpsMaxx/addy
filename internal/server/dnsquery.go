package server

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"time"
)

// A DNS A-record query that does NOT consult /etc/hosts.
//
// Go's resolver always reads the hosts file first, in both the pure-Go and cgo
// paths, and there is no option to skip it. That is correct for a program
// resolving a name in order to CONNECT to it, and wrong for a preflight, whose
// whole question is what the rest of the world sees: on a Contabo box the
// hosts file maps the public hostname to 127.0.1.1, so every resolver Go
// offers reports a loopback address for a name that resolves perfectly well in
// public.
//
// Sixty lines rather than a DNS library, because the query is one question of
// one type to a resolver we chose, and the parser only has to handle the reply
// to that. It is deliberately strict: anything it does not expect is an error
// rather than a guess, since a wrong answer here sends an operator to debug
// DNS that is already correct.

const dnsMaxReply = 512 // one UDP datagram; we ask for nothing that needs more

// queryA asks one resolver for A records, bypassing the hosts file.
func queryA(ctx context.Context, server, name string) ([]string, error) {
	msg, err := buildQuery(name)
	if err != nil {
		return nil, err
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(5 * time.Second)
	}
	_ = conn.SetDeadline(deadline)

	if _, err := conn.Write(msg); err != nil {
		return nil, err
	}
	reply := make([]byte, dnsMaxReply)
	n, err := conn.Read(reply)
	if err != nil {
		return nil, err
	}
	return parseA(msg[:2], reply[:n])
}

func buildQuery(name string) ([]byte, error) {
	out := make([]byte, 0, 32+len(name))
	id := uint16(rand.N(1 << 16))
	var header [12]byte
	binary.BigEndian.PutUint16(header[0:], id)
	binary.BigEndian.PutUint16(header[2:], 0x0100) // recursion desired
	binary.BigEndian.PutUint16(header[4:], 1)      // one question
	out = append(out, header[:]...)

	for _, label := range splitLabels(name) {
		if len(label) == 0 || len(label) > 63 {
			return nil, fmt.Errorf("server: %q is not a hostname this can ask about", name)
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0)          // root label
	out = append(out, 0, 1, 0, 1) // QTYPE A, QCLASS IN
	return out, nil
}

func splitLabels(name string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			if i > start {
				out = append(out, name[start:i])
			}
			start = i + 1
		}
	}
	return out
}

// parseA walks the reply. Strict: an unexpected shape is an error, never a
// partial answer, because a preflight that reports half a truth is worse than
// one that says it could not tell.
func parseA(wantID []byte, reply []byte) ([]string, error) {
	if len(reply) < 12 {
		return nil, errors.New("server: the DNS reply is too short to be one")
	}
	if reply[0] != wantID[0] || reply[1] != wantID[1] {
		// Not our question. A resolver does not do this; something in the
		// middle might, and answering somebody else's query as though it were
		// ours is the one thing that must not happen silently.
		return nil, errors.New("server: the DNS reply answers a different query")
	}
	if rcode := reply[3] & 0x0f; rcode == 3 {
		return nil, errors.New("no such name")
	} else if rcode != 0 {
		return nil, fmt.Errorf("server: the resolver answered rcode %d", rcode)
	}

	questions := binary.BigEndian.Uint16(reply[4:])
	answers := binary.BigEndian.Uint16(reply[6:])
	pos := 12
	for i := 0; i < int(questions); i++ {
		var err error
		if pos, err = skipName(reply, pos); err != nil {
			return nil, err
		}
		pos += 4 // QTYPE + QCLASS
	}

	var out []string
	for i := 0; i < int(answers); i++ {
		var err error
		if pos, err = skipName(reply, pos); err != nil {
			return nil, err
		}
		if pos+10 > len(reply) {
			return nil, errors.New("server: the DNS reply is truncated")
		}
		rtype := binary.BigEndian.Uint16(reply[pos:])
		rdlen := int(binary.BigEndian.Uint16(reply[pos+8:]))
		pos += 10
		if pos+rdlen > len(reply) {
			return nil, errors.New("server: a DNS record runs past the end of the reply")
		}
		// Type 1 is A. Anything else -- a CNAME in the chain, most often -- is
		// skipped rather than followed: the resolver has already followed it
		// and the A records are in the same answer section.
		if rtype == 1 && rdlen == 4 {
			out = append(out, net.IP(reply[pos:pos+4]).String())
		}
		pos += rdlen
	}
	if len(out) == 0 {
		return nil, errors.New("no A record")
	}
	return out, nil
}

// skipName walks a name, following at most one compression pointer.
//
// One, not a loop: a pointer chain is how a malicious reply makes a parser
// spin forever, and a legitimate reply never needs more than one from here.
func skipName(msg []byte, pos int) (int, error) {
	for {
		if pos >= len(msg) {
			return 0, errors.New("server: a DNS name runs past the end of the reply")
		}
		length := int(msg[pos])
		switch {
		case length == 0:
			return pos + 1, nil
		case length&0xc0 == 0xc0:
			// A pointer. The name ends here as far as the caller is concerned.
			if pos+1 >= len(msg) {
				return 0, errors.New("server: a DNS compression pointer is truncated")
			}
			return pos + 2, nil
		case length > 63:
			return 0, errors.New("server: a DNS label is too long")
		default:
			pos += 1 + length
		}
	}
}

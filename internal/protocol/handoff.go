package protocol

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/subtle"
	"errors"
	"fmt"

	"crypto/hpke"
)

// The pairing handoff: what an already-trusted device seals to a newly paired
// one.
//
// SPEC CORRECTION, 2026-09-17, found by implementing it. PROTOCOL.md section
// 8.7 says the handoff plaintext is "the addy-escrow-v1\0 structure" with a
// different HPKE info label. Section 10.1 says the joining device "receives
// RK_sign.pub in the same sealed structure". The escrow structure has no field
// for it, so both cannot be true.
//
// Resolved with a structure of its own, addy-handoff-v1\0, rather than by
// adding an optional field to the escrow. Two structures that differ by a field
// and share a domain prefix are two structures a verifier can be confused
// between; two structures with different prefixes are not.
//
// WHY RK_sign.pub HAS TO TRAVEL. A joining device must verify the roster chain
// from genesis, and step 8 of that algorithm needs the root key to check
// root-signed entries. It cannot take that key from the server -- a chain
// verified against a key the server supplied is not verified. So it comes
// sealed, from a device that already holds it.

const (
	domainHandoffPlaintext = "addy-handoff-v1"
	domainHandoffAAD       = "addy-handoff-aad-v1"
	domainHandoffObject    = "addy-handoff-obj-v1"

	infoHandoffHPKE   = "addy-handoff-hpke-v1"
	infoHandoffCommit = "addy-handoff-commit-v1"
)

// Handoff is everything a newly paired device needs and cannot compute.
type Handoff struct {
	AccountID   AccountID
	Epoch       uint64
	Counter     uint64 // the sealing device's current escrow counter
	AKSeed      []byte // fixed[32]
	RootSignPub []byte // fixed[32]; needed to verify root-signed roster entries
	HeadEntry   []byte // the roster head, body || sig, verbatim
}

func (h Handoff) encodePlaintext() ([]byte, error) {
	if err := fixed("ak_seed", h.AKSeed, 32); err != nil {
		return nil, err
	}
	if err := fixed("rk_sign_pub", h.RootSignPub, ed25519.PublicKeySize); err != nil {
		return nil, err
	}
	if len(h.HeadEntry) == 0 {
		return nil, errors.New("protocol: a handoff with no roster head entry")
	}
	if h.Counter == 0 {
		return nil, errors.New("protocol: handoff counters start at 1")
	}
	return NewEncoder(domainHandoffPlaintext).
		Fixed(h.AccountID[:]).
		U64(h.Epoch).
		U64(h.Counter).
		Fixed(h.AKSeed).
		Fixed(h.RootSignPub).
		Bytes(h.HeadEntry).
		Out(), nil
}

func (h Handoff) aad() []byte {
	return NewEncoder(domainHandoffAAD).
		Fixed(h.AccountID[:]).
		U64(h.Epoch).
		U64(h.Counter).
		Out()
}

// SealHandoff seals to the joining device's DK_enc.
//
// NOTHING IS SEALED BEFORE THE HUMAN CONFIRMS THE EMOJI. That ordering is the
// whole value of the confirmation step, and it is the caller's to enforce --
// this function is what must not be called early.
func SealHandoff(h Handoff, recipient *ecdh.PublicKey) ([]byte, error) {
	plaintext, err := h.encodePlaintext()
	if err != nil {
		return nil, err
	}
	pk, err := hpke.NewDHKEMPublicKey(recipient)
	if err != nil {
		return nil, fmt.Errorf("protocol: handoff recipient key: %w", err)
	}
	kdf, aead := suite()
	enc, sender, err := hpke.NewSender(pk, kdf, aead, info(infoHandoffHPKE, &h.AccountID, h.Epoch))
	if err != nil {
		return nil, fmt.Errorf("protocol: handoff sender: %w", err)
	}
	ct, err := sender.Seal(h.aad(), plaintext)
	if err != nil {
		return nil, fmt.Errorf("protocol: sealing the handoff: %w", err)
	}
	commit, err := sender.Export(handoffCommitContext(h.AccountID, h.Epoch, h.Counter), commitLen)
	if err != nil {
		return nil, fmt.Errorf("protocol: handoff commitment: %w", err)
	}
	return NewEncoder(domainHandoffObject).
		U8(SuitePinned).
		Bytes(enc).
		Fixed(commit).
		Bytes(ct).
		Out(), nil
}

func handoffCommitContext(acct AccountID, epoch, counter uint64) string {
	return string(NewEncoder(infoHandoffCommit).
		Fixed(acct[:]).
		U64(epoch).
		U64(counter).
		Out())
}

// OpenHandoff opens what a trusted device sealed, on the joining device.
//
// Same commitment discipline as the escrow: the exporter tag is compared in
// constant time BEFORE the AEAD, so a chosen ciphertext fails before it
// produces any plaintext at all rather than being noticed afterwards.
func OpenHandoff(object []byte, acct AccountID, epoch, counter uint64, recipient *ecdh.PrivateKey) (*Handoff, error) {
	if counter == 0 {
		return nil, errors.New("handoff: counters start at 1")
	}

	d := NewDecoder(domainHandoffObject, object)
	gotSuite := d.U8()
	enc := d.Bytes()
	commit := d.Fixed(commitLen)
	ct := d.Bytes()
	if err := d.End(); err != nil {
		return nil, fmt.Errorf("handoff: %w", err)
	}
	if gotSuite != SuitePinned {
		return nil, fmt.Errorf("%w: %#02x", ErrEscrowSuite, gotSuite)
	}

	sk, err := hpke.NewDHKEMPrivateKey(recipient)
	if err != nil {
		return nil, fmt.Errorf("handoff: recipient key: %w", err)
	}
	kdf, aead := suite()
	r, err := hpke.NewRecipient(enc, sk, kdf, aead, info(infoHandoffHPKE, &acct, epoch))
	if err != nil {
		return nil, fmt.Errorf("handoff: recipient context: %w", err)
	}

	want, err := r.Export(handoffCommitContext(acct, epoch, counter), commitLen)
	if err != nil {
		return nil, fmt.Errorf("handoff: commitment: %w", err)
	}
	if subtle.ConstantTimeCompare(want, commit) != 1 {
		return nil, ErrEscrowCommit
	}

	plaintext, err := r.Open(Handoff{AccountID: acct, Epoch: epoch, Counter: counter}.aad(), ct)
	if err != nil {
		return nil, fmt.Errorf("handoff: opening: %w", err)
	}

	pd := NewDecoder(domainHandoffPlaintext, plaintext)
	var out Handoff
	copy(out.AccountID[:], pd.Fixed(AccountIDLen))
	out.Epoch = pd.U64()
	out.Counter = pd.U64()
	out.AKSeed = pd.Fixed(32)
	out.RootSignPub = pd.Fixed(ed25519.PublicKeySize)
	out.HeadEntry = pd.Bytes()
	if err := pd.End(); err != nil {
		return nil, fmt.Errorf("handoff: plaintext: %w", err)
	}
	if out.AccountID != acct || out.Epoch != epoch || out.Counter != counter {
		return nil, ErrEscrowMismatch
	}

	// The account id must be the one this root key names. Without this a device
	// could be handed a valid-looking handoff for a DIFFERENT account and would
	// go on to verify that account's chain quite happily.
	if DeriveAccountID(out.RootSignPub) != out.AccountID {
		return nil, fmt.Errorf("%w: the root key does not name this account", ErrWrongAccount)
	}
	return &out, nil
}

// Adopt turns a handoff into the keys and the verified chain a joining device
// needs, and is where the joiner stops trusting the device that paired it.
//
// The chain is verified from genesis against the root key and the epoch key the
// HANDOFF carried, not against anything the server said. A chain verified
// against a key the server supplied is not verified.
func (h *Handoff) Adopt(chain []byte) (*EpochKeys, *Verified, error) {
	keys, err := DeriveEpoch(h.AKSeed, h.AccountID, h.Epoch)
	if err != nil {
		return nil, nil, err
	}

	// Epoch 1's signing key is what genesis was signed with. If this handoff is
	// for a later epoch, the chain establishes the earlier keys as it is
	// verified -- but epoch 1's has to come from somewhere, and for a joining
	// device that is the genesis entry itself, which the handoff's head entry
	// does not necessarily contain.
	//
	// So: when the handoff is for epoch 1, the key derived above IS epoch 1's.
	// For a later epoch the joiner asks the pairing device for the chain and
	// verifies it against the root key, which covers every root-signed
	// transition; a hygiene rotation chain still needs epoch 1, and that case
	// is why a joining device is given the chain by a device that holds it
	// rather than fetching it cold.
	var epoch1 ed25519.PublicKey
	if h.Epoch == 1 {
		epoch1 = keys.Sign.Public().(ed25519.PublicKey)
	}

	v, err := VerifyChain(chain, h.AccountID, h.RootSignPub, epoch1, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("handoff: the chain did not verify: %w", err)
	}
	return keys, v, nil
}

package protocol

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

// The end-to-end story this whole package exists for: a first device mints an
// account offline, a second device is handed the account key, and the second
// device verifies the chain FROM GENESIS against keys it was given by the first
// -- never against anything the server said.
func TestASecondDeviceIsAdmittedAndVerifiesTheChainItself(t *testing.T) {
	// Device A: genesis.
	a, err := NewAccount("quiet-otter-41")
	if err != nil {
		t.Fatal(err)
	}

	// Device B: mints its own keys, locally. They are derived from nothing.
	b, err := NewDeviceKeys()
	if err != nil {
		t.Fatal(err)
	}
	bPubSign := b.Sign.Public().(ed25519.PublicKey)
	bPubEnc := b.Enc.PublicKey().Bytes()

	// A appends B to the roster, signed by the epoch key.
	prev, err := a.Genesis.Hash()
	if err != nil {
		t.Fatal(err)
	}
	labelCT, err := SealLabel("brave-pylon-07", a.Root.AccountID, 1, bPubSign, a.Epoch.Profile)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := Nonce()
	if err != nil {
		t.Fatal(err)
	}
	add := Entry{
		AccountID: a.Root.AccountID, Epoch: 1, Seq: 1, PrevHash: prev,
		Op: OpAdd, Signer: SignerAK, Nonce: nonce,
		PubSign: bPubSign, PubEnc: bPubEnc, LabelCT: labelCT, TS: 2,
	}
	body, err := add.Encode()
	if err != nil {
		t.Fatal(err)
	}
	add.Sig = ed25519.Sign(a.Epoch.Sign, body)

	genesisWire, err := a.Genesis.Wire()
	if err != nil {
		t.Fatal(err)
	}
	addWire, err := add.Wire()
	if err != nil {
		t.Fatal(err)
	}
	chain := append(genesisWire, addWire...)

	// A seals the handoff to B's encryption key. Nothing is sealed before the
	// human confirms the emoji; that ordering is the caller's to enforce.
	head, err := add.Hash()
	if err != nil {
		t.Fatal(err)
	}
	_ = head
	obj, err := SealHandoff(Handoff{
		AccountID:   a.Root.AccountID,
		Epoch:       1,
		Counter:     1,
		AKSeed:      a.Epoch.AK,
		RootSignPub: a.Root.Sign.Public().(ed25519.PublicKey),
		HeadEntry:   addWire,
	}, b.Enc.PublicKey())
	if err != nil {
		t.Fatalf("SealHandoff: %v", err)
	}

	// B opens it and adopts.
	h, err := OpenHandoff(obj, a.Root.AccountID, 1, 1, b.Enc)
	if err != nil {
		t.Fatalf("OpenHandoff: %v", err)
	}
	keys, v, err := h.Adopt(chain)
	if err != nil {
		t.Fatalf("Adopt: %v", err)
	}

	// B now holds the same epoch key and sees both devices.
	if !bytes.Equal(keys.AK, a.Epoch.AK) {
		t.Error("the joining device did not receive the account's epoch key")
	}
	if !bytes.Equal(keys.Profile, a.Epoch.Profile) {
		t.Error("the joining device derived a different profile key")
	}
	if len(v.Devices) != 2 {
		t.Fatalf("the joining device sees %d devices, want 2", len(v.Devices))
	}

	// And it can read the labels, which is what makes a revoke dialog name a
	// device rather than a key.
	for _, d := range v.Devices {
		if _, err := OpenLabel(d.LabelCT, h.AccountID, 1, d.PubSign, keys.Profile); err != nil {
			t.Errorf("the joining device cannot read a device label: %v", err)
		}
	}
}

// A device must not be handed a valid-looking handoff for a DIFFERENT account
// and go on to verify that account's chain quite happily.
func TestAHandoffWhoseRootKeyDoesNotNameItsAccountIsRefused(t *testing.T) {
	a, err := NewAccount("one")
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewAccount("two")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewDeviceKeys()
	if err != nil {
		t.Fatal(err)
	}
	wire, err := a.Genesis.Wire()
	if err != nil {
		t.Fatal(err)
	}

	obj, err := SealHandoff(Handoff{
		AccountID: a.Root.AccountID,
		Epoch:     1, Counter: 1,
		AKSeed: a.Epoch.AK,
		// Somebody else's root key.
		RootSignPub: other.Root.Sign.Public().(ed25519.PublicKey),
		HeadEntry:   wire,
	}, b.Enc.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	if _, err := OpenHandoff(obj, a.Root.AccountID, 1, 1, b.Enc); !errors.Is(err, ErrWrongAccount) {
		t.Fatalf("OpenHandoff = %v, want ErrWrongAccount", err)
	}
}

// Same commitment discipline as the escrow: a wrong key fails at the
// commitment, before the AEAD produces any plaintext.
func TestAHandoffSealedToAnotherDeviceFailsAtTheCommitment(t *testing.T) {
	a, err := NewAccount("one")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewDeviceKeys()
	if err != nil {
		t.Fatal(err)
	}
	wire, err := a.Genesis.Wire()
	if err != nil {
		t.Fatal(err)
	}
	obj, err := SealHandoff(Handoff{
		AccountID: a.Root.AccountID, Epoch: 1, Counter: 1,
		AKSeed:      a.Epoch.AK,
		RootSignPub: a.Root.Sign.Public().(ed25519.PublicKey),
		HeadEntry:   wire,
	}, b.Enc.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	stranger, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenHandoff(obj, a.Root.AccountID, 1, 1, stranger); !errors.Is(err, ErrEscrowCommit) {
		t.Fatalf("OpenHandoff = %v, want ErrEscrowCommit", err)
	}
}

// A handoff and an escrow must not be interchangeable. They carry different
// fields and have different domain prefixes precisely so a verifier cannot be
// confused between them.
func TestAHandoffIsNotAnEscrow(t *testing.T) {
	a, err := NewAccount("one")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewDeviceKeys()
	if err != nil {
		t.Fatal(err)
	}
	wire, err := a.Genesis.Wire()
	if err != nil {
		t.Fatal(err)
	}
	handoff, err := SealHandoff(Handoff{
		AccountID: a.Root.AccountID, Epoch: 1, Counter: 1,
		AKSeed:      a.Epoch.AK,
		RootSignPub: a.Root.Sign.Public().(ed25519.PublicKey),
		HeadEntry:   wire,
	}, b.Enc.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	if _, err := OpenEscrow(handoff, a.Root.AccountID, 1, 1, b.Enc, 0); err == nil {
		t.Fatal("a handoff opened as an escrow")
	}
	if _, err := OpenHandoff(a.Escrow, a.Root.AccountID, 1, 1, a.Root.Enc); err == nil {
		t.Fatal("an escrow opened as a handoff")
	}
}

// The joining device must verify the chain against the key the HANDOFF carried,
// so a server serving a different chain is caught.
func TestTheJoiningDeviceRefusesAnotherAccountsChain(t *testing.T) {
	a, err := NewAccount("one")
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewAccount("two")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewDeviceKeys()
	if err != nil {
		t.Fatal(err)
	}
	wire, err := a.Genesis.Wire()
	if err != nil {
		t.Fatal(err)
	}
	obj, err := SealHandoff(Handoff{
		AccountID: a.Root.AccountID, Epoch: 1, Counter: 1,
		AKSeed:      a.Epoch.AK,
		RootSignPub: a.Root.Sign.Public().(ed25519.PublicKey),
		HeadEntry:   wire,
	}, b.Enc.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	h, err := OpenHandoff(obj, a.Root.AccountID, 1, 1, b.Enc)
	if err != nil {
		t.Fatal(err)
	}

	theirChain, err := other.Genesis.Wire()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.Adopt(theirChain); err == nil {
		t.Fatal("the joining device adopted another account's chain")
	}
}

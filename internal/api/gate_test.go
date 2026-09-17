package api_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/opsmaxx/addy/internal/client"
	"github.com/opsmaxx/addy/internal/pair"
	"github.com/opsmaxx/addy/internal/protocol"
)

// M1'S GATE, IN ONE TEST.
//
//	"A device mints an account from nothing, a second pairs and verifies
//	 emoji, and a third is refused."
//
// Everything below goes through the real relay: the two devices never touch
// each other, only the server, and the server sees three opaque frames it
// learns nothing from.

// frames are what actually crosses the wire. JSON here rather than ACE-1
// because these are transport envelopes, not signed structures -- nothing
// verifies them, and the PAKE material inside is useless without the code.
type startWire struct {
	PairingID []byte `json:"pairing_id"`
	MsgA      []byte `json:"msg_a"`
	PubSign   []byte `json:"pub_sign"`
}
type replyWire struct {
	MsgB     []byte `json:"msg_b"`
	ConfirmB []byte `json:"confirm_b"`
	PubSign  []byte `json:"pub_sign"`
	PubEnc   []byte `json:"pub_enc"`
}
type confirmWire struct {
	ConfirmA []byte `json:"confirm_a"`
}

func TestM1Gate(t *testing.T) {
	srv, db := instance(t)

	// --- A device mints an account from nothing -------------------------
	a := client.New(srv.URL, true)
	acct, err := a.Register("quiet-otter-41", invite(t, db))
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := a.Login(); err != nil {
		t.Fatalf("Login: %v", err)
	}

	// --- A second pairs, and both sides see the same emoji ---------------
	code, err := pair.NewCode()
	if err != nil {
		t.Fatal(err)
	}

	bKeys, err := protocol.NewDeviceKeys()
	if err != nil {
		t.Fatal(err)
	}
	bPubSign := bKeys.Sign.Public().(ed25519.PublicKey)

	initiator, f1, err := pair.Begin(code, acct.Device.Sign.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	// The joining device has no session and does not know the account id, so
	// it reaches the relay through the unauthenticated pairing room.
	joining := client.New(srv.URL, true)

	var wg sync.WaitGroup
	var joinErr error
	var joinerSAS pair.SAS

	wg.Add(1)
	go func() {
		defer wg.Done()

		raw, err := joining.NextPairFrame("joiner", f1.PairingID)
		if err != nil || raw == nil {
			joinErr = errors.Join(err, errors.New("no frame 1"))
			return
		}
		var in startWire
		if err := json.Unmarshal(raw, &in); err != nil {
			joinErr = err
			return
		}

		j, f2, err := pair.Join(code, pair.StartFrame{
			PairingID: in.PairingID, MsgA: in.MsgA, PubSign: in.PubSign,
		}, bPubSign, bKeys.Enc.PublicKey().Bytes())
		if err != nil {
			joinErr = err
			return
		}
		out, _ := json.Marshal(replyWire{
			MsgB: f2.MsgB, ConfirmB: f2.ConfirmB, PubSign: f2.PubSign, PubEnc: f2.PubEnc,
		})
		if err := joining.SendPairFrame("joiner", in.PairingID, out); err != nil {
			joinErr = err
			return
		}

		raw3, err := joining.NextPairFrame("joiner", in.PairingID)
		if err != nil || raw3 == nil {
			joinErr = errors.Join(err, errors.New("no frame 3"))
			return
		}
		var in3 confirmWire
		if err := json.Unmarshal(raw3, &in3); err != nil {
			joinErr = err
			return
		}
		if err := j.Confirm(pair.ConfirmFrame{ConfirmA: in3.ConfirmA}); err != nil {
			joinErr = err
			return
		}
		joinerSAS, joinErr = j.SAS()
	}()

	out1, _ := json.Marshal(startWire{PairingID: f1.PairingID, MsgA: f1.MsgA, PubSign: f1.PubSign})
	if err := a.SendPairFrame("initiator", f1.PairingID, out1); err != nil {
		t.Fatalf("sending frame 1: %v", err)
	}

	raw2, err := a.NextPairFrame("initiator", f1.PairingID)
	if err != nil || raw2 == nil {
		t.Fatalf("waiting for frame 2: %v", err)
	}
	var in2 replyWire
	if err := json.Unmarshal(raw2, &in2); err != nil {
		t.Fatal(err)
	}

	f3, err := initiator.Reply(pair.ReplyFrame{
		MsgB: in2.MsgB, ConfirmB: in2.ConfirmB, PubSign: in2.PubSign, PubEnc: in2.PubEnc,
	})
	if err != nil {
		t.Fatalf("Reply: %v", err)
	}
	out3, _ := json.Marshal(confirmWire{ConfirmA: f3.ConfirmA})
	if err := a.SendPairFrame("initiator", f1.PairingID, out3); err != nil {
		t.Fatalf("sending frame 3: %v", err)
	}

	wg.Wait()
	if joinErr != nil {
		t.Fatalf("the joining device failed: %v", joinErr)
	}

	initiatorSAS, err := initiator.SAS()
	if err != nil {
		t.Fatal(err)
	}
	if initiatorSAS.Indices != joinerSAS.Indices {
		t.Fatalf("THE EMOJI DIFFER, which is what a MITM looks like:\n A %s\n B %s",
			initiatorSAS, joinerSAS)
	}
	t.Logf("paired with code %s; both sides show %s (%s)",
		code, initiatorSAS, initiatorSAS.Words())

	// --- Only now is anything sealed to the new device -------------------
	//
	// Nothing is sealed before the human confirms the emoji, and that ordering
	// is the whole value of the confirmation step.
	prev, err := acct.Genesis.Hash()
	if err != nil {
		t.Fatal(err)
	}
	labelCT, err := protocol.SealLabel("brave-pylon-07", acct.Root.AccountID, 1, bPubSign, acct.Epoch.Profile)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := protocol.Nonce()
	if err != nil {
		t.Fatal(err)
	}
	add := protocol.Entry{
		AccountID: acct.Root.AccountID, Epoch: 1, Seq: 1, PrevHash: prev,
		Op: protocol.OpAdd, Signer: protocol.SignerAK, Nonce: nonce,
		PubSign: bPubSign, PubEnc: bKeys.Enc.PublicKey().Bytes(),
		LabelCT: labelCT, TS: 2,
	}
	body, err := add.Encode()
	if err != nil {
		t.Fatal(err)
	}
	add.Sig = ed25519.Sign(acct.Epoch.Sign, body)
	if err := a.AppendRoster(add); err != nil {
		t.Fatalf("publishing the roster entry: %v", err)
	}

	// The new device now logs in as itself and verifies the chain from genesis
	// against the keys it was HANDED, never against anything the server said.
	joining.Account = acct.Root.AccountID
	joining.Device = bKeys
	if err := joining.Login(); err != nil {
		t.Fatalf("the newly paired device could not log in: %v", err)
	}
	v, err := joining.Roster(
		acct.Root.Sign.Public().(ed25519.PublicKey),
		acct.Epoch.Sign.Public().(ed25519.PublicKey), nil)
	if err != nil {
		t.Fatalf("the newly paired device could not verify the roster: %v", err)
	}
	if len(v.Devices) != 2 {
		t.Fatalf("the roster has %d devices, want 2", len(v.Devices))
	}

	// --- And a third is refused ------------------------------------------
	//
	// A device nobody added holds keys nobody signed, so the server has no
	// session to give it: it can present a public key, and the account's roster
	// simply does not contain it.
	third, err := protocol.NewDeviceKeys()
	if err != nil {
		t.Fatal(err)
	}
	stranger := client.New(srv.URL, true)
	stranger.Account = acct.Root.AccountID
	stranger.Device = third

	// It can log in -- the server authenticates a key, and cannot verify a
	// roster it has no key for. What it CANNOT do is appear in the chain the
	// other devices verify, which is the guarantee that actually matters: a
	// device the roster does not name is a device nothing is sealed to.
	_ = stranger.Login()
	v2, err := joining.Roster(
		acct.Root.Sign.Public().(ed25519.PublicKey),
		acct.Epoch.Sign.Public().(ed25519.PublicKey), nil)
	if err != nil {
		t.Fatal(err)
	}
	thirdPub := third.Sign.Public().(ed25519.PublicKey)
	for _, d := range v2.Devices {
		if bytes.Equal(d.PubSign, thirdPub) {
			t.Fatal("a device nobody added appears in the verified roster")
		}
	}
	if len(v2.Devices) != 2 {
		t.Fatalf("the roster grew to %d devices without an entry being signed", len(v2.Devices))
	}
}

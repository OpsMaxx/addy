package api_test

import (
	"testing"
	"time"

	"github.com/opsmaxx/addy/internal/client"
)

// A change on one device reaches the other, as a POINTER -- the collection, the
// epoch and the revision, and no ciphertext. The receiving client compares its
// revision and decides whether to fetch.
func TestAChangeOnOneDeviceReachesTheOther(t *testing.T) {
	srv, db := instance(t)

	a := client.New(srv.URL, true)
	acct, err := a.Register("quiet-otter-41", invite(t, db))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Login(); err != nil {
		t.Fatal(err)
	}

	// A second device of the same account.
	b, _ := addedDevice(t, srv.URL, a, acct)

	got := make(chan []client.Notification, 1)
	go func() {
		n, err := b.Changes()
		if err != nil {
			t.Errorf("Changes: %v", err)
		}
		got <- n
	}()

	// Give the subscriber a moment to be waiting.
	time.Sleep(50 * time.Millisecond)
	if _, err := a.PutObject("servers", 1, 7, []byte("sealed bytes"), ""); err != nil {
		t.Fatalf("PutObject: %v", err)
	}

	select {
	case notes := <-got:
		if len(notes) != 1 {
			t.Fatalf("%d notifications, want 1", len(notes))
		}
		n := notes[0]
		if n.Collection != "servers" || n.Revision != 7 || n.Epoch != 1 {
			t.Errorf("notification = %+v", n)
		}
		// A POINTER, NOT A PAYLOAD. Nothing in the struct can carry ciphertext,
		// which is the property that makes a dropped notification harmless.
		if n.Actor == "" {
			t.Error("the notification does not name the acting device")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no notification arrived")
	}
}

// FREE ECHO SUPPRESSION: one field, no bookkeeping. Without it every write a
// device makes comes back to it as a change to fetch.
func TestADeviceDoesNotHearItsOwnWrites(t *testing.T) {
	srv, db := instance(t)
	a := client.New(srv.URL, true)
	if _, err := a.Register("quiet-otter-41", invite(t, db)); err != nil {
		t.Fatal(err)
	}
	if err := a.Login(); err != nil {
		t.Fatal(err)
	}

	got := make(chan []client.Notification, 1)
	go func() {
		n, _ := a.Changes()
		got <- n
	}()
	time.Sleep(50 * time.Millisecond)
	if _, err := a.PutObject("servers", 1, 1, []byte("x"), ""); err != nil {
		t.Fatal(err)
	}

	select {
	case notes := <-got:
		if len(notes) != 0 {
			t.Errorf("a device heard its own write: %+v", notes)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the poll never returned")
	}
}

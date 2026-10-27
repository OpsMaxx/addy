package frontdoor

import "testing"

// Renewals keep the TLS key.
//
// Devices pin the certificate's public key and sign over it at every login.
// certmagic's default is a new key per renewal, which every paired device
// would read as a man-in-the-middle about every sixty days, with the recovery
// phrase as the only way back. This is the line that stops it.
func TestRenewalsReuseTheKeyDevicesPin(t *testing.T) {
	_, _, magic, err := NewACME(ACMEConfig{DataDir: t.TempDir(), Routes: NewTable()})
	if err != nil {
		t.Fatal(err)
	}
	if !magic.ReusePrivateKeys {
		t.Fatal("certmagic will mint a new key at renewal, and every device's pin will stop matching")
	}
}

package wallet

import (
	"reflect"
	"testing"
)

func TestRawKeyIdentity(t *testing.T) {
	// New Raw identity
	id := "did:example:3dda540891d14a1baec2c7485c273c00"
	keyID := "keys-1"
	privateKeyHex := "a889f4da49ff8dd6b03d4334723fe3e5ff55ae6a2483de1627bec873b0b73e1e86eabd6abce2f96553251de61def0265784688ff712ce583621a5b181ef21639"
	publicKeyHex := "86eabd6abce2f96553251de61def0265784688ff712ce583621a5b181ef21639"
	key := &Key{
		ID:            keyID,
		Type:          Ed25519KeyType,
		PrivateKeyHex: privateKeyHex,
		PublicKeyHex:  publicKeyHex,
	}
	x, _ := NewRawKeyIdentity(id, key)

	// Assert version
	if x.Version() != rawKeyV1 {
		t.Fatalf("The version of the Raw identity should be %v", rawKeyV1)
	}

	// Assert type
	if x.Type() != RawIdentityType {
		t.Fatalf("The type of the Raw identity should be %v", RawIdentityType)
	}

	// Assert did
	if x.Did() != id {
		t.Fatalf("The Did of the Raw identity should be %v", id)
	}

	// Assert key ID
	if x.KeyID() != keyID {
		t.Fatalf("The key ID of the Raw identity should be %v", keyID)
	}

	// Asert key type
	if x.KeyType() != Ed25519KeyType {
		t.Fatalf("The key type of the Raw identity should be %v", Ed25519KeyType)
	}

	// Assert private key content
	if x.PrivateKeyHex() != privateKeyHex {
		t.Fatal("The private key of the Raw identity mismatched")
	}

	// Asert public key content
	if x.PublicKeyHex() != publicKeyHex {
		t.Fatal("The public key of the Raw identity mismatched")
	}

	// Test Marshal method
	data, err := x.Marshal()
	if err != nil {
		t.Fatalf("Marshal the Raw identity failed: %v", err)
	}

	// Test Unmarshal method
	xx, err := x.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal the Raw identity failed: %v", err)
	}

	if !reflect.DeepEqual(x, xx) {
		t.Fatal("The Raw identity marshal and unmarshal test failed")
	}
}

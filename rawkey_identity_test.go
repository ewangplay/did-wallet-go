package wallet

import (
	"sort"
	"reflect"
	"testing"
)

func TestRawKeyIdentity(t *testing.T) {
	// New RawKey identity
	id := "did:example:3dda540891d14a1baec2c7485c273c00"
	keyID1 := "did:example:3dda540891d14a1baec2c7485c273c00#keys-1"
	privateKeyHex1 := "a889f4da49ff8dd6b03d4334723fe3e5ff55ae6a2483de1627bec873b0b73e1e86eabd6abce2f96553251de61def0265784688ff712ce583621a5b181ef21639"
	publicKeyHex1 := "86eabd6abce2f96553251de61def0265784688ff712ce583621a5b181ef21639"
	keyID2 := "did:example:3dda540891d14a1baec2c7485c273c00#keys-2"
	privateKeyHex2 := "475446b1f11109413e6983ba05121821912200a7b9046bd6764e408a2371362043e10c88d8ec4011bea186912725f066b1222c5797eec64b3378b337f313b425"
	publicKeyHex2 := "43e10c88d8ec4011bea186912725f066b1222c5797eec64b3378b337f313b425"
	keys := []*Key{
		&Key{
			ID:            keyID1,
			Type:          "Ed25519",
			PrivateKeyHex: privateKeyHex1,
			PublicKeyHex:  publicKeyHex1,
		},
		&Key{
			ID:            keyID2,
			Type:          "Ed25519",
			PrivateKeyHex: privateKeyHex2,
			PublicKeyHex:  publicKeyHex2,
		},
	}
	x, _ := NewRawKeyIdentity(id, keys)

	// Assert version
	if x.Version() != rawKeyV1 {
		t.Fatalf("The version of the RawKey identity should be %v", rawKeyV1)
	}

	// Assert type
	if x.Type() != rawKeyType {
		t.Fatalf("The type of the RawKey identity should be %v", rawKeyType)
	}

	// Assert did
	if x.Did() != id {
		t.Fatalf("Did of the RawKey identity should be %v", id)
	}

	// Test GetKey method
	k, err := x.GetKey(keyID1)
	if err != nil {
		t.Fatalf("Get key failed: %v", err)
	}
	if k.ID != keyID1 {
		t.Fatal("Key id mismatched")
	}
	if k.Type != "Ed25519" {
		t.Fatal("Key type mismatched")
	}
	if k.PrivateKeyHex != privateKeyHex1 {
		t.Fatal("Private key content mismatched")
	}
	if k.PublicKeyHex != publicKeyHex1 {
		t.Fatal("Private key content mismatched")
	}

	// Test RemoveKey method
	err = x.RemoveKey(keyID1)
	if err != nil {
		t.Fatalf("Remove Key failed: %v", err)
	}

	// keyID1 has been removed, so should not be retrieved
	_, err = x.GetKey(keyID1)
	if err == nil {
		t.Fatalf("Key %s should not exist in KeySotre", keyID1)
	}

	// Put keyID1 back to the KeyStore
	err = x.PutKey(keyID1, k)
	if err != nil {
		t.Fatalf("Put key failed: %v", err)
	}

	// Now the keyID1 can be retrieved again
	kk, err := x.GetKey(keyID1)
	if err != nil || kk == nil {
		t.Fatalf("Key %s should exist in KeySotre", keyID1)
	}

	// Test ListKey method
	expected := []string{keyID1, keyID2}
	result, err := x.ListKey()
	if err != nil {
		t.Fatalf("List key failed: %v", err)
	}
	sort.Strings(result)
	if !reflect.DeepEqual(result, expected) {
		t.Fatalf("key list mismatched, actual: %v, expected: %v", result, expected)
	}

	// Test Marshal method
	data, err := x.Marshal()
	if err != nil {
		t.Fatalf("Marshal the RawKey identity failed: %v", err)
	}

	// Test Unmarshal method
	xx, err := x.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal the RawKey identity failed: %v", err)
	}

	if !reflect.DeepEqual(x, xx) {
		t.Fatal("The RawKey identity marshal and unmarshal test failed")
	}
}

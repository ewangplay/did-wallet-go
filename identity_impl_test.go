package wallet

import (
	"encoding/json"
	"reflect"
	"testing"

	io "github.com/ewangplay/serval/io"
)

const (
	did      = "did:example:fafdecaa29934fde9dcc5adaea8ea82b"
	keysJson = `
	[
		{
			"id" : "did:example:fafdecaa29934fde9dcc5adaea8ea82b#keys-1",
			"type" : "Ed25519",
			"privateKeyHex" : "905f6f3c113b9303bc50c310509bb4272e1e7ab83da8b019f7707ae1a1c189584cd5d192e33f390d7f2a5cc948103a080c52f42fefe2d4d334f86e7ac78e0938",
			"publicKeyHex" : "4cd5d192e33f390d7f2a5cc948103a080c52f42fefe2d4d334f86e7ac78e0938"
		},
		{
			"id" : "did:example:fafdecaa29934fde9dcc5adaea8ea82b#keys-2",
			"type" : "Ed25519",
			"privateKeyHex" : "5aca741c5d1265e28c35610c68cc1ca2d8b76fd1e3794590968cf6dd13cc8c8de1df3e6e58d51ba0217137224d6daef2a5d1a5790b6537d6f9830d59639e0826",
			"publicKeyHex" : "e1df3e6e58d51ba0217137224d6daef2a5d1a5790b6537d6f9830d59639e0826"
		}
	]
	`
)

func TestNewIdentity(t *testing.T) {
	t.Run("New Ed25519 Identity", func(t *testing.T) {
		var err error
		var keys []*io.Key
		err = json.Unmarshal([]byte(keysJson), &keys)
		if err != nil {
			t.Fatalf("Unmarshal keys failed: %v", err)
		}

		x, err := NewIdentity(did, keys)
		if err != nil {
			t.Fatalf("New identity failed: %v", err)
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
	})
}

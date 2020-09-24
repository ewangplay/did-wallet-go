package wallet

import (
	"encoding/json"
	"fmt"
)

const rawKeyV1 = 1

// RawIdentity represents an raw identity with public and private key pair
type RawIdentity struct {
	Ver    int          `json:"version"`
	ID     string       `json:"id"`
	IDType IdentityType `json:"type"`
	Key    Key          `json:"key"`
}

// Key represents the key pair
type Key struct {
	ID            string  `json:"id"`
	Type          KeyType `json:"type"`
	PrivateKeyHex string  `json:"privateKeyHex"`
	PublicKeyHex  string  `json:"publicKeyHex"`
}

// Version returns the version of this identity
func (x *RawIdentity) Version() int {
	return x.Ver
}

// Type returns the type of this identity
func (x *RawIdentity) Type() IdentityType {
	return x.IDType
}

// Did returns did of this identity
func (x *RawIdentity) Did() string {
	return x.ID
}

// KeyID returns the ID of this identity
func (x *RawIdentity) KeyID() string {
	return x.Key.ID
}

// KeyType returns the key type of this identity
func (x *RawIdentity) KeyType() KeyType {
	return x.Key.Type
}

// PrivateKeyHex returns the private key hexadecimal format of this identity
func (x *RawIdentity) PrivateKeyHex() string {
	return x.Key.PrivateKeyHex
}

// PublicKeyHex returns the public key hexadecimal format of this identity
func (x *RawIdentity) PublicKeyHex() string {
	return x.Key.PublicKeyHex
}

// NewRawIdentity creates an Raw identity for storage in a wallet
func NewRawIdentity(id string, key *Key) (*RawIdentity, error) {
	if id == "" {
		return nil, fmt.Errorf("id must not be empty")
	}
	if key == nil {
		return nil, fmt.Errorf("key must not be empty")
	}

	return &RawIdentity{rawKeyV1, id, RawIdentityType, *key}, nil
}

// Marshal returns the JSON encoding of this identity
func (x *RawIdentity) Marshal() ([]byte, error) {
	return json.Marshal(x)
}

// Unmarshal parses the JSON-encoded data to this identity and returns it
func (x *RawIdentity) Unmarshal(data []byte) (Identity, error) {
	err := json.Unmarshal(data, x)

	if err != nil {
		return nil, err
	}

	return x, nil
}

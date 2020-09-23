package wallet

import (
	"encoding/json"
	"fmt"
)

const rawKeyType = "RawKey"
const rawKeyV1 = 1

// RawKeyIdentity represents an RawKey identity
type RawKeyIdentity struct {
	Ver    int             `json:"version"`
	ID     string          `json:"id"`
	IDType string          `json:"type"`
	Keys   map[string]*Key `json:"keys"`
}

// Key represents the key pair
type Key struct {
	ID            string `json:"id"`
	Type          string `json:"type"`
	PrivateKeyHex string `json:"privateKeyHex"`
	PublicKeyHex  string `json:"publicKeyHex"`
}

// Version returns the version of this identity
func (x *RawKeyIdentity) Version() int {
	return x.Ver
}

// Type returns the type of this identity
func (x *RawKeyIdentity) Type() string {
	return x.IDType
}

// Did returns did of this identity
func (x *RawKeyIdentity) Did() string {
	return x.ID
}

// PutKey puts an new key into the KeyStore
// If it already exists in the KeyStore, it will override it.
//
func (x *RawKeyIdentity) PutKey(id string, key *Key) error {
	x.Keys[id] = key
	return nil
}

// GetKey returns the specified key according to the key id
func (x *RawKeyIdentity) GetKey(id string) (*Key, error) {
	if key, ok := x.Keys[id]; ok {
		return key, nil
	}
	return nil, fmt.Errorf("key %v doesn't exist", id)
}

// RemoveKey removes the specified key from the KeyStore
func (x *RawKeyIdentity) RemoveKey(id string) error {
	if _, ok := x.Keys[id]; ok {
		delete(x.Keys, id)
		return nil
	}
	return nil
}

// ListKey lists all of the keys in KeyStore
func (x *RawKeyIdentity) ListKey() ([]string, error) {
	ids := make([]string, 0, len(x.Keys))
	for id := range x.Keys {
		ids = append(ids, id)
	}
	return ids, nil
}

// NewRawKeyIdentity creates an RawKey identity for storage in a wallet
func NewRawKeyIdentity(id string, keys []*Key) (*RawKeyIdentity, error) {
	if id == "" {
		return nil, fmt.Errorf("id must not be empty")
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("keys must not be empty")
	}

	mKeys := make(map[string]*Key, len(keys))
	for _, key := range keys {
		mKeys[key.ID] = key
	}

	return &RawKeyIdentity{rawKeyV1, id, rawKeyType, mKeys}, nil
}

// Marshal returns the JSON encoding of this identity
func (x *RawKeyIdentity) Marshal() ([]byte, error) {
	return json.Marshal(x)
}

// Unmarshal parses the JSON-encoded data to this identity and returns it
func (x *RawKeyIdentity) Unmarshal(data []byte) (Identity, error) {
	err := json.Unmarshal(data, x)

	if err != nil {
		return nil, err
	}

	return x, nil
}

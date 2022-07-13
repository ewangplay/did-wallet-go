package wallet

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	cl "github.com/ewangplay/cryptolib"
	io "github.com/ewangplay/serval/io"
)

// Identity represents an identity with public and private key pair
type Identity struct {
	ID         string `json:"id"`
	MasterKey  io.Key `json:"master_key"`
	StandbyKey io.Key `json:"slave_key"`
}

// NewIdentity creates an identity according to the identity type
func NewIdentity(id string, keys []*io.Key) (*Identity, error) {
	if id == "" {
		return nil, fmt.Errorf("id cannot be empty")
	}
	if len(keys) < 2 {
		return nil, fmt.Errorf("the number of keys is incorrect")
	}
	identity := &Identity{
		ID:         id,
		MasterKey:  *keys[0],
		StandbyKey: *keys[1],
	}
	return identity, nil
}

// Did returns did of this identity
func (x *Identity) Did() string {
	return x.ID
}

// Marshal returns the JSON encoding of this identity
func (x *Identity) Marshal() ([]byte, error) {
	return json.Marshal(x)
}

// Unmarshal parses the JSON-encoded data to this identity and returns it
func (x *Identity) Unmarshal(data []byte) (IIdentity, error) {
	err := json.Unmarshal(data, x)
	if err != nil {
		return nil, err
	}
	return x, nil
}

func (x *Identity) GetMasterKeyID() string {
	return x.MasterKey.ID
}

func (x *Identity) GetMasterKey() (k cl.Key, err error) {
	kBytes, err := hex.DecodeString(x.MasterKey.PrivateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("master private key (%v) is invalid: %v", x.MasterKey.ID, err)
	}

	switch x.MasterKey.Type {
	case cl.ED25519:
		k = &cl.Ed25519PrivateKey{
			PrivKey: kBytes,
		}
	default:
		return nil, fmt.Errorf("master private key (%v) has unsupported type: %v", x.MasterKey.ID, x.MasterKey.Type)
	}

	return
}

func (x *Identity) GetStandbyKeyID() string {
	return x.StandbyKey.ID
}

func (x *Identity) GetStandbyKey() (k cl.Key, err error) {
	kBytes, err := hex.DecodeString(x.StandbyKey.PrivateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("standby private key (%v) is invalid: %v", x.StandbyKey.ID, err)
	}

	switch x.StandbyKey.Type {
	case cl.ED25519:
		k = &cl.Ed25519PrivateKey{
			PrivKey: kBytes,
		}
	default:
		return nil, fmt.Errorf("standby private key (%v) has unsupported type: %v", x.StandbyKey.ID, x.StandbyKey.Type)
	}

	return
}

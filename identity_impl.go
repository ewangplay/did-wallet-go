package wallet

import (
	"encoding/json"
	"fmt"

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

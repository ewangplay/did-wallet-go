package wallet

import "encoding/json"

const x509Type = "X.509"
const x509V1 = 1

// X509Identity represents an X509 identity
type X509Identity struct {
	Ver         int         `json:"version"`
	ID          string      `json:"id"`
	IDType      string      `json:"type"`
	Credentials credentials `json:"credentials"`
}

type credentials struct {
	Certificate string `json:"certificate"`
	Key         string `json:"privateKey"`
}

// Version returns the current version for this identity type
func (x *X509Identity) Version() int {
	return x.Ver
}

// Type returns X509 for this identity type
func (x *X509Identity) Type() string {
	return x.IDType
}

// Did returns did of this identity
func (x *X509Identity) Did() string {
	return x.ID
}

// Certificate returns the X509 certificate PEM
func (x *X509Identity) Certificate() string {
	return x.Credentials.Certificate
}

// Key returns the private key PEM
func (x *X509Identity) Key() string {
	return x.Credentials.Key
}

// NewX509Identity creates an X509 identity for storage in a wallet
func NewX509Identity(id string, cert string, key string) *X509Identity {
	return &X509Identity{x509V1, id, x509Type, credentials{cert, key}}
}

// Marshal returns the JSON encoding of this identity
func (x *X509Identity) Marshal() ([]byte, error) {
	return json.Marshal(x)
}

// Unmarshal parses the JSON-encoded data to this identity and returns it
func (x *X509Identity) Unmarshal(data []byte) (Identity, error) {
	err := json.Unmarshal(data, x)

	if err != nil {
		return nil, err
	}

	return x, nil
}

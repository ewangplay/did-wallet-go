package wallet

import (
	cl "github.com/ewangplay/cryptolib"
)

// Identity represents a did identity
type IIdentity interface {
	Did() string
	Marshal() ([]byte, error)
	Unmarshal(data []byte) (IIdentity, error)

	GetMasterKeyID() string
	GetMasterKey() (cl.Key, error)

	GetStandbyKeyID() string
	GetStandbyKey() (cl.Key, error)
}

package wallet

// Identity represents a did identity
type IIdentity interface {
	Did() string
	Marshal() ([]byte, error)
	Unmarshal(data []byte) (IIdentity, error)
}

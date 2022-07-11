package wallet

// Store is the interface for implementations that provide backing storage for identities in a wallet.
type Store interface {
	Put(label string, stream []byte) error
	Get(label string) ([]byte, error)
	List() ([]string, error)
	Exists(label string) bool
	Remove(label string) error
}

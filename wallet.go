package wallet

import (
	"encoding/json"
	"fmt"
)

// wallet represents a did wallet
type wallet interface {
	Put(label string, id Identity) error
	Get(label string) (Identity, error)
	Remove(label string) error
	Exists(label string) bool
	List() ([]string, error)
}

// Identity represents a did identity
type Identity interface {
	Version() int
	Type() string
	Did() string
	Marshal() ([]byte, error)
	Unmarshal(data []byte) (Identity, error)
}

// WalletStore is the interface for implementations that provide backing storage for identities in a wallet.
type WalletStore interface {
	Put(label string, stream []byte) error
	Get(label string) ([]byte, error)
	List() ([]string, error)
	Exists(label string) bool
	Remove(label string) error
}

// A Wallet stores identity information.
type Wallet struct {
	store WalletStore
}

// Put an identity into the wallet
//  Parameters:
//  label specifies the name to be associated with the identity.
//  id specifies the identity to store in the wallet.
func (w *Wallet) Put(label string, id Identity) error {
	content, err := id.Marshal()
	if err != nil {
		return err
	}

	return w.store.Put(label, content)
}

// Get an identity from the wallet. The implementation class of the identity object will vary depending on its type.
//  Parameters:
//  label specifies the name of the identity in the wallet.
//
//  Returns:
//  The identity object.
func (w *Wallet) Get(label string) (Identity, error) {
	content, err := w.store.Get(label)

	if err != nil {
		return nil, err
	}

	var data map[string]interface{}
	if err := json.Unmarshal(content, &data); err != nil {
		return nil, fmt.Errorf("invalid identity format: %v", err)
	}

	idType, ok := data["type"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid identity format: missing type property")
	}

	var id Identity
	switch idType {
	case x509Type:
		id = &X509Identity{}
	case rawKeyType:
		id = &RawKeyIdentity{}
	default:
		return nil, fmt.Errorf("invalid identity format: unsupported identity type: " + idType)
	}

	return id.Unmarshal(content)
}

// List returns the labels of all identities in the wallet.
//
//  Returns:
//  A list of identity labels in the wallet.
func (w *Wallet) List() ([]string, error) {
	return w.store.List()
}

// Exists tests whether the wallet contains an identity for the given label.
//  Parameters:
//  label specifies the name of the identity in the wallet.
//
//  Returns:
//  True if the named identity is in the wallet.
func (w *Wallet) Exists(label string) bool {
	return w.store.Exists(label)
}

// Remove an identity from the wallet. If the identity does not exist, this method does nothing.
//  Parameters:
//  label specifies the name of the identity in the wallet.
func (w *Wallet) Remove(label string) error {
	return w.store.Remove(label)
}

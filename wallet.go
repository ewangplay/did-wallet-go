package wallet

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	cl "github.com/ewangplay/cryptolib"
	"github.com/ewangplay/serval/io"
	sdk "github.com/ewangplay/serval/sdk/go"
	"github.com/ewangplay/serval/utils"
)

// A Wallet stores identity information.
type Wallet struct {
	store  Store
	client *sdk.Client
	csp    cl.CSP
}

func NewWallet(addr string, store Store) (*Wallet, error) {
	if addr == "" {
		return nil, fmt.Errorf("did network addr must be set")
	}

	// The a Store instance is not set, use the file system store as default.
	var err error
	if store == nil {
		store, err = NewFileSystemStore("./wallet")
		if err != nil {
			return nil, err
		}
	}

	// New did network client
	client, err := sdk.NewClient(addr)
	if err != nil {
		return nil, err
	}

	// Get the default CSP instance
	csp, err := cl.GetCSP(nil)
	if err != nil {
		return nil, err
	}

	return &Wallet{store, client, csp}, nil
}

func (w *Wallet) CreateAccount() (string, error) {
	var identity IIdentity
	var err error

	// Generate did materials
	did, ddo, keys, err := w.genDidMaterials()
	if err != nil {
		return "", err
	}

	// New an identity instance
	identity, err = NewIdentity(did, keys)
	if err != nil {
		return "", err
	}

	// Push the did/ddo record to network
	req := &io.CreateDidReq{
		Did:      did,
		Document: *ddo,
	}
	err = w.client.CreateDid(req)
	if err != nil {
		return "", err
	}

	// Put the identity to local store
	err = w.Put(identity.Did(), identity)
	if err != nil {
		return "", err
	}

	return did, nil
}

func (w *Wallet) genDidMaterials() (did string, ddo *io.DDO, keys []*io.Key, err error) {

	// Generate DID
	methodName := "example"
	methodSpecificID := strings.ReplaceAll(utils.GenerateUUID(), "-", "")
	did = fmt.Sprintf("did:%s:%s", methodName, methodSpecificID)

	// Generate master public / private key pair
	key1 := fmt.Sprintf("%s#keys-1", did)
	priKey1, err := w.csp.KeyGen(&cl.ED25519KeyGenOpts{})
	if err != nil {
		return
	}
	priKey1Bytes, err := priKey1.Bytes()
	if err != nil {
		return
	}
	pubKey1, err := priKey1.PublicKey()
	if err != nil {
		return
	}
	pubKey1Bytes, err := pubKey1.Bytes()
	if err != nil {
		return
	}

	// Generate standby public / private key pair
	key2 := fmt.Sprintf("%s#keys-2", did)
	priKey2, err := w.csp.KeyGen(&cl.ED25519KeyGenOpts{})
	if err != nil {
		return
	}
	priKey2Bytes, err := priKey2.Bytes()
	if err != nil {
		return
	}
	pubKey2, err := priKey2.PublicKey()
	if err != nil {
		return
	}
	pubKey2Bytes, err := pubKey2.Bytes()
	if err != nil {
		return
	}
	// Use master private key to sign did
	// Once an entity's DID is generated,
	// it does not change, so signing did is appropriate.
	signature, err := w.csp.Sign(priKey1, []byte(did), nil)
	if err != nil {
		return
	}

	// Build DID Document
	now := time.Now()
	ddo = &io.DDO{
		Context: "https://www.w3.org/ns/did/v1",
		ID:      did,
		Version: 1,
		PublicKey: []io.PublicKey{
			{
				ID:           key1,
				Type:         cl.ED25519,
				PublicKeyHex: hex.EncodeToString(pubKey1Bytes),
			},
			{
				ID:           key2,
				Type:         cl.ED25519,
				PublicKeyHex: hex.EncodeToString(pubKey2Bytes),
			},
		},
		Controller:     did,
		Authentication: []string{key1},
		Recovery:       []string{key2},
		Proof: io.Proof{
			Type:           cl.ED25519,
			Creator:        key1,
			SignatureValue: base64.StdEncoding.EncodeToString(signature),
		},
		Created: now,
		Updated: now,
	}

	// Response body
	keys = []*io.Key{
		{
			ID:            key1,
			Type:          cl.ED25519,
			PrivateKeyHex: hex.EncodeToString(priKey1Bytes),
			PublicKeyHex:  hex.EncodeToString(pubKey1Bytes),
		},
		{
			ID:            key2,
			Type:          cl.ED25519,
			PrivateKeyHex: hex.EncodeToString(priKey2Bytes),
			PublicKeyHex:  hex.EncodeToString(pubKey2Bytes),
		},
	}

	return
}

func (w *Wallet) RemoveAccount(did string) error {
	return nil
}

// Put an identity into the wallet
//  Parameters:
//  label specifies the name to be associated with the identity.
//  id specifies the identity to store in the wallet.
func (w *Wallet) Put(label string, id IIdentity) error {
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
func (w *Wallet) Get(label string) (IIdentity, error) {
	content, err := w.store.Get(label)
	if err != nil {
		return nil, err
	}

	var id Identity
	return id.Unmarshal(content)
}

// List returns the labels of all identities in the wallet.
//
//  Returns:
//  A list of identity labels in the wallet.
func (w *Wallet) ListAccount() ([]string, error) {
	return w.store.List()
}

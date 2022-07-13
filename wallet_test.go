package wallet_test

import (
	"strings"
	"testing"

	wallet "github.com/ewangplay/did-wallet"
)

const (
	addr = "localhost:8099"
)

func newWallet(t *testing.T) *wallet.Wallet {
	w, err := wallet.NewWallet(addr, nil)
	if err != nil {
		if strings.Contains(err.Error(), "connection refused") {
			t.Skip()
		}
		t.Fatal(err)
	}
	return w
}

func TestCreateAccount(t *testing.T) {
	var err error
	var did string

	w := newWallet(t)

	t.Run("CreateAccount", func(t *testing.T) {
		did, err = w.CreateAccount()
		if err != nil {
			t.Fatal(err)
		}
		t.Log(did)
	})

	t.Run("RemoveAccount", func(t *testing.T) {
		err = w.RemoveAccount(did)
		if err != nil {
			t.Fatal(err)
		}
	})
}

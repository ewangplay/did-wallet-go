package wallet_test

import (
	"strings"
	"testing"

	wallet "github.com/ewangplay/did-wallet"
)

const (
	addr = "localhost:8099"
)

func TestCreateAccount(t *testing.T) {
	w, err := wallet.NewWallet(addr, nil)
	if err != nil {
		if strings.Contains(err.Error(), "connection refused") {
			t.Skip()
		}
		t.Fatal(err)
	}

	t.Run("CreateAccount", func(t *testing.T) {
		did, err := w.CreateAccount()
		if err != nil {
			t.Fatal(err)
		}
		t.Log(did)
	})
}

func TestRemoveAccount(t *testing.T) {
	t.Skip()
}

func TestListAccount(t *testing.T) {
	t.Skip()
}

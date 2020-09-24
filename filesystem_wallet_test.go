package wallet

import (
	"os"
	"path/filepath"
	"testing"
)

func createFileSystemWallet() (*Wallet, error) {
	dir := filepath.Join("testdata", "wallet", "unit")
	os.RemoveAll(dir)
	return NewFileSystemWallet(dir)
}

func TestFileSystemWalletSuite(t *testing.T) {
	testWalletSuite(t, createFileSystemWallet)
	os.RemoveAll(filepath.Join("testdata", "wallet", "unit"))
}

func TestFormatCompatibility(t *testing.T) {
	dir := filepath.Join("testdata", "wallet")
	wallet, err := NewFileSystemWallet(dir)
	if err != nil {
		t.Fatalf("Failed to create FileSystemWallet: %s", err)
	}

	id, err := wallet.Get("x509-v1")
	if err != nil {
		t.Fatalf("Failed to get identity from FileSystemWallet: %s", err)
	}

	x509 := id.(*X509Identity)

	if x509.Did() != "did:example:3dda540891d14a1baec2c7485c273c00" {
		t.Fatalf("Incorrect MspID: %s", x509.Did())
	}

	if x509.Type() != X509IdentityType {
		t.Fatalf("Incorrect IDType: %s", x509.Type())
	}

	if x509.Version() != x509V1 {
		t.Fatalf("Incorrect version: %d", x509.Version())
	}
}

func TestNonJSONFormat(t *testing.T) {
	dir := filepath.Join("testdata", "wallet")
	wallet, err := NewFileSystemWallet(dir)
	if err != nil {
		t.Fatalf("Failed to create FileSystemWallet: %s", err)
	}

	_, err = wallet.Get("invalid1")
	if err == nil {
		t.Fatal("Expected error to be thrown")
	}
}

func TestInvalidJSONFormat(t *testing.T) {
	dir := filepath.Join("testdata", "wallet")
	wallet, err := NewFileSystemWallet(dir)
	if err != nil {
		t.Fatalf("Failed to create FileSystemWallet: %s", err)
	}

	_, err = wallet.Get("invalid2")
	if err == nil {
		t.Fatal("Expected error to be thrown")
	}
}

func TestMissingTypeFormat(t *testing.T) {
	dir := filepath.Join("testdata", "wallet")
	wallet, err := NewFileSystemWallet(dir)
	if err != nil {
		t.Fatalf("Failed to create FileSystemWallet: %s", err)
	}

	_, err = wallet.Get("invalid3")
	if err == nil {
		t.Fatal("Expected error to be thrown")
	}
}

func TestInvalidTypeFormat(t *testing.T) {
	dir := filepath.Join("testdata", "wallet")
	wallet, err := NewFileSystemWallet(dir)
	if err != nil {
		t.Fatalf("Failed to create FileSystemWallet: %s", err)
	}

	_, err = wallet.Get("invalid4")
	if err == nil {
		t.Fatal("Expected error to be thrown")
	}
}

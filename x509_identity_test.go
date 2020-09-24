package wallet

import (
	"reflect"
	"testing"
)

func TestX509Identity(t *testing.T) {
	id := "did:example:3dda540891d14a1baec2c7485c273c00"
	cert := "testCert"
	key := "testPrivKey"
	x, _ := NewX509Identity(id, cert, key)

	if x.Version() != x509V1 {
		t.Fatalf("The version of the X509 identity should be %v", x509V1)
	}

	if x.Type() != X509IdentityType {
		t.Fatalf("The type of the X509 identity should be %v", X509IdentityType)
	}

	if x.Did() != id {
		t.Fatalf("Did of the X509 identity should be %v", id)
	}

	if x.Certificate() != cert {
		t.Fatalf("The certificate of the X509 identity should be %v", cert)
	}

	if x.Key() != key {
		t.Fatalf("The private key of the X509 identity should be %v", cert)
	}

	data, err := x.Marshal()
	if err != nil {
		t.Fatalf("Marshal the X509 identity failed: %v", err)
	}

	xx, err := x.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal the X509 identity failed: %v", err)
	}

	if !reflect.DeepEqual(x, xx) {
		t.Fatal("The X509 identity marshal and unmarshal test failed")
	}
}

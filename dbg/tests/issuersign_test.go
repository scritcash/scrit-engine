package tests

import (
	"scrit/issuer"
	"scrit/keydir"
	"scrit/types"
	"testing"
)

type testKeyPublisher struct{}

func (self *testKeyPublisher) Publish(serializedDBCCert []byte) error {
	// fmt.Printf("SerializedDBCCert: %x\n", serializedDBCCert)
	return nil
}

func TestIssue(t *testing.T) {
	blindsuite := types.Nist256()
	options := &issuer.IssuerOptions{
		KnownIssuers:  nil,
		BlindSuite:    blindsuite,
		ValidDuration: 1000,
		KeyManager:    new(testKeyManager),
		KeyPublisher:  new(testKeyPublisher),
	}
	issuer, err := issuer.NewIssuer(options)
	if err != nil {
		t.Fatalf("NewIssuer: %s", err)
	}
	token, err := issuer.Issue(nil, keydir.Currency("EUR"), keydir.Value(10))
	if err != nil {
		t.Errorf("Issue: %s", err)
	}
	_ = token
}

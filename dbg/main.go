package main

import (
	"fmt"
	"scrit/issuer"
	"scrit/keydir"
	"scrit/types"
)

type testKeyPublisher struct{}

func (self *testKeyPublisher) Publish(serializedDBCCert []byte) error {
	// fmt.Printf("SerializedDBCCert: %x\n", serializedDBCCert)
	return nil
}

type testKeyManager struct{}

func (s testKeyManager) Factory() (keyID uint64, key *[types.KeySize]byte) {
	ret := [32]byte{0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x02, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x03, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x10, 0x11}
	return 1, &ret
}

func (s testKeyManager) Lookup(keyID uint64) (key *[types.KeySize]byte) {
	_, key = s.Factory()
	return
}

func main() {
	options := &issuer.IssuerOptions{
		KnownIssuers:  nil,
		BlindSuite:    types.Nist256(),
		ValidDuration: 1000,
		KeyManager:    new(testKeyManager),
		KeyPublisher:  new(testKeyPublisher),
	}
	issuer, err := issuer.NewIssuer(options)
	if err != nil {
		panic(err)
	}
	token, err := issuer.Issue(nil, keydir.Currency("EUR"), keydir.Value(10))
	if err != nil {
		fmt.Printf("Issue: %s\n", err)
	}
	_ = token
}

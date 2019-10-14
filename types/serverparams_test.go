package types

import (
	"bytes"
	"crypto/rand"
	"testing"

	"scrit/blind"
)

type testKeyManager struct{}

func (s testKeyManager) Factory() (keyID uint64, key *[KeySize]byte) {
	ret := [32]byte{0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x02, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x03, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x10, 0x11}
	return 1, &ret
}

func (s testKeyManager) Lookup(keyID uint64) (key *[KeySize]byte) {
	_, key = s.Factory()
	return
}

func TestServerParams(t *testing.T) {
	suite, err := New(SuiteNist256)
	if err != nil {
		t.Fatalf("New Suite: %s", err)
	}

	kp2, err := blind.NewCurve(suite.Curve()).GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("NewCurve: %s", err)
	}

	serverParams, err := suite.MarshalServerParams(kp2.Public, kp2.Secret, testKeyManager{})
	if err != nil {
		t.Errorf("MarshalServerParams: %s", err)
	}
	blindParam, suite2, err := UnmarshalServerParams(serverParams)
	if err != nil {
		t.Errorf("UnmarshalServerParams: %s", err)
	}
	if suite.CurveID != suite2.CurveID {
		t.Errorf("UnmarshalServerParams, curves do not match: %x != %x", suite.CurveID, suite2.CurveID)
	}
	if !kp2.Public.Cmp(blindParam) {
		t.Error("Points dont match blindParam")
	}

	secret, suite2, err := UnmarshalMyServerParams(serverParams, testKeyManager{})
	if err != nil {
		t.Errorf("UnmarshalMyServerParams: %s", err)
	}
	if suite.CurveID != suite2.CurveID {
		t.Errorf("UnmarshalServerParams, curves do not match: %x != %x", suite.CurveID, suite2.CurveID)
	}
	if !bytes.Equal(kp2.Secret.Marshal(), secret.Marshal()) {
		t.Error("Server secret does not match")
	}

}

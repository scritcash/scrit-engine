package types

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"testing"

	"scrit/blind"
)

func TestSerializePubkey(t *testing.T) {
	suite, err := New(SuiteNist256)
	if err != nil {
		t.Fatalf("New Suite: %s", err)
	}
	signer, err := blind.NewSigner(suite.Curve(), rand.Reader)
	if err != nil {
		t.Fatalf("NewSigner: %s", err)
	}
	publicKey := signer.Public()
	pkM := suite.MarshalPubKey(publicKey)
	publicKey2, bs, err := UnmarshalPubKey(pkM)
	if err != nil {
		t.Errorf("Unmarshal: %s", err)
	}
	if bs.CurveID != suite.CurveID {
		t.Errorf("Unmarshal, curves do not match: %x != %x", bs.CurveID, suite.CurveID)
	}
	if !publicKey.Cmp(publicKey2) {
		t.Error("Unmarshal, points dont match")
	}
}

func TestSerializeBlindSignature(t *testing.T) {
	suite, err := New(SuiteNist256)
	if err != nil {
		t.Fatalf("New Suite: %s", err)
	}
	signer, err := blind.NewSigner(suite.Curve(), rand.Reader)
	if err != nil {
		t.Fatalf("NewSigner: %s", err)
	}
	publicKey := signer.Public()
	s := (*blind.Skalar)(big.NewInt(39812))
	bsig := suite.MarshalBlindSignature(s, publicKey)
	s2, publicKey2, bs, err := UnmarshalBlindSignature(bsig)
	if err != nil {
		t.Errorf("UnmarshalBlindSignature: %s", err)
	}
	if bs.CurveID != suite.CurveID {
		t.Errorf("Unmarshal, curves do not match: %x != %x", bs.CurveID, suite.CurveID)
	}
	if (*big.Int)(s).Cmp((*big.Int)(s2)) != 0 {
		t.Error("BlindSignature differs")
	}
	if !publicKey.Cmp(publicKey2) {
		t.Error("Public key")
	}
}

func TestSerializeSignature(t *testing.T) {
	s := (*blind.Skalar)(big.NewInt(39812))
	suite, err := New(SuiteNist256)
	if err != nil {
		t.Fatalf("New Suite: %s", err)
	}
	signer, err := blind.NewSigner(suite.Curve(), rand.Reader)
	if err != nil {
		t.Fatalf("NewSigner: %s", err)
	}
	publicKey := signer.Public()
	ss := suite.MarshalSignature(publicKey, s, publicKey)
	publicKey2, s2, r2, bs, err := UnmarshalSignature(ss)
	if err != nil {
		t.Fatalf("UnmarshalSignature: %s", err)
	}
	if bs.CurveID != suite.CurveID {
		t.Errorf("Unmarshal, curves do not match: %x != %x", bs.CurveID, suite.CurveID)
	}
	if (*big.Int)(s).Cmp((*big.Int)(s2)) != 0 {
		t.Error("Signature differs")
	}
	if !publicKey.Cmp(publicKey2) {
		t.Error("Unmarshal, points dont match publickey")
	}
	if !publicKey.Cmp(r2) {
		t.Error("Unmarshal, points dont match r")
	}
}

func TestSignatureRequest(t *testing.T) {
	s := (*blind.Skalar)(big.NewInt(39812))
	m := []byte{0x01, 0x02, 0x03, 0x04}
	n := []byte{0x10, 0x20, 0x30, 0x40}
	suite, err := New(SuiteNist256)
	if err != nil {
		t.Fatalf("New Suite: %s", err)
	}
	signer, err := blind.NewSigner(suite.Curve(), rand.Reader)
	if err != nil {
		t.Fatalf("NewSigner: %s", err)
	}
	publicKey := signer.Public()
	public, private := suite.MarshalSignatureRequest(s, m, n, publicKey)
	s2, suite2, err := UnmarshalSignatureRequestPublic(public)
	if err != nil {
		t.Fatalf("UnmarshalSignatureRequestPublic: %s", err)
	}
	if suite2.CurveID != suite.CurveID {
		t.Errorf("Unmarshal, curves do not match: %x != %x", suite2.CurveID, suite.CurveID)
	}
	if (*big.Int)(s).Cmp((*big.Int)(s2)) != 0 {
		t.Error("Signature differs")
	}
	m2, n2, publicKey2, suite3, err := UnmarshalSignatureRequestPrivate(private)
	if err != nil {
		t.Fatalf("UnmarshalSignatureRequestPrivate: %s", err)
	}
	if !publicKey.Cmp(publicKey2) {
		t.Error("Unmarshal, points dont match publickey")
	}
	if suite3.CurveID != suite.CurveID {
		t.Errorf("Unmarshal, curves do not match: %x != %x", suite2.CurveID, suite.CurveID)
	}
	if !bytes.Equal(m, m2) {
		t.Error("M decode failed")
	}
	if !bytes.Equal(n, n2) {
		t.Error("N decode failed")
	}
}

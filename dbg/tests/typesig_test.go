package tests

import (
	"crypto/rand"
	"scrit/blind"
	"scrit/types"
	"testing"
)

func TestSign(t *testing.T) {
	msgHash := []byte{0x01, 0x02, 0x03}
	suite, err := types.New(types.SuiteNist256)
	if err != nil {
		t.Fatalf("New Suite: %s", err)
	}
	curve := suite.Curve()
	signer, err := blind.NewSigner(curve, rand.Reader)
	if err != nil {
		t.Fatalf("NewSigner: %s", err)
	}
	publicKey := signer.Public()
	Q, k, err := signer.SignatureParams()
	if err != nil {
		t.Fatalf("SignatureParam: %s", err)
	}
	marshalledServerParams, err := suite.MarshalServerParams(Q, k, testKeyManager{})
	if err != nil {
		t.Fatalf("MarshalServerParams: %s", err)
	}
	Q, suite2, err := types.UnmarshalServerParams(marshalledServerParams)
	if err != nil {
		t.Fatalf("UnmarshalServerParams: %s", err)
	}
	// signRequest, m, n, err := blind.BlindSignRequest(curve, rand.Reader, Q, msgHash)
	signRequest, m, n, err := blind.BlindSignRequest(suite2.Curve(), rand.Reader, Q, msgHash)
	if err != nil {
		t.Fatalf("BlindSignRequest: %s", err)
	}
	public, private := suite.MarshalSignatureRequest(signRequest, m, n, Q)
	signRequest2, suite, err := types.UnmarshalSignatureRequestPublic(public)
	if err != nil {
		t.Fatalf("UnmarshalSignatureRequestPublic: %s", err)
	}
	k2, suite, err := types.UnmarshalMyServerParams(marshalledServerParams, testKeyManager{})
	if err != nil {
		t.Fatalf("UnmarshalMyServerParams: %s", err)
	}
	// blindSignature, err := signer.Sign(k, signRequest)
	blindSignature, err := signer.Sign(k2, signRequest2)
	if err != nil {
		t.Fatalf("Sign: %s", err)
	}
	blindSig := suite.MarshalBlindSignature(blindSignature, publicKey)
	blindSig2, publicKey2, suite, err := types.UnmarshalBlindSignature(blindSig)
	if err != nil {
		t.Fatalf("UnmarshalBlindSignature: %s", err)
	}
	m2, n2, Q2, suite, err := types.UnmarshalSignatureRequestPrivate(private)
	if err != nil {
		t.Fatalf("UnmarshalSignatureRequestPrivate: %s", err)
	}
	// s, R := blind.UnblindSignature(curve, Q, msgHash, blindSignature, m, n)
	s, R := blind.UnblindSignature(suite.Curve(), Q2, msgHash, blindSig2, m2, n2)
	signatureM := suite.MarshalSignature(publicKey2, s, R)
	pubkey3, s2, R2, suite, err := types.UnmarshalSignature(signatureM)
	if err != nil {
		t.Fatalf("UnmarshalSignature: %s", err)
	}
	if !blind.VerifySignature(suite.Curve(), pubkey3, msgHash, s2, R2) {
		t.Error("VerifySignature")
	}
}

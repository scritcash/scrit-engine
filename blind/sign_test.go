package blind

import (
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec"
)

func fullTest(t *testing.T, curve elliptic.Curve) {
	msgHash := []byte{0x01, 0x02, 0x03}
	signer, err := NewSigner(curve, rand.Reader)
	if err != nil {
		t.Fatalf("NewSigner: %s", err)
	}
	publicKey := signer.Public()
	for i := 0; i < 1000; i++ {
		Q, k, err := signer.SignatureParams()
		if err != nil {
			t.Fatalf("SignatureParam: %s", err)
		}
		signRequest, m, n, err := BlindSignRequest(curve, rand.Reader, Q, msgHash)
		if err != nil {
			t.Fatalf("BlindSignRequest: %s", err)
		}
		blindSignature, err := signer.Sign(k, signRequest)
		if err != nil {
			t.Fatalf("Sign: %s", err)
		}
		s, R := UnblindSignature(curve, Q, msgHash, blindSignature, m, n)
		if !VerifySignature(curve, publicKey, msgHash, s, R) {
			t.Error("VerifySignature")
		}
	}
}

func sizeTest(t *testing.T, curve elliptic.Curve) {
	msgHash := []byte{0x01, 0x02, 0x03}
	signer, err := NewSigner(curve, rand.Reader)
	if err != nil {
		t.Fatalf("NewSigner: %s", err)
	}
	publicKey := signer.Public()
	fmt.Printf("PubKey: %d\n", len(publicKey.Marshal()))
	Q, k, err := signer.SignatureParams()
	if err != nil {
		t.Fatalf("SignatureParam: %s", err)
	}
	fmt.Printf("SigParams Q: %d, k: %d\n", len(Q.Marshal()), len(k.Marshal()))
	signRequest, m, n, err := BlindSignRequest(curve, rand.Reader, Q, msgHash)
	if err != nil {
		t.Fatalf("BlindSignRequest: %s", err)
	}
	fmt.Printf("BlindSigRequest sR: %d, m: %d, n: %d\n", len(((*big.Int)(signRequest)).Bytes()), len(m), len(n))
	blindSignature, err := signer.Sign(k, signRequest)
	if err != nil {
		t.Fatalf("Sign: %s", err)
	}
	fmt.Printf("BlindSig: %d\n", len(((*big.Int)(blindSignature)).Bytes()))
	s, R := UnblindSignature(curve, Q, msgHash, blindSignature, m, n)
	if !VerifySignature(curve, publicKey, msgHash, s, R) {
		t.Error("VerifySignature")
	}
	fmt.Printf("Signature s: %d, R: %d\n", len(((*big.Int)(s)).Bytes()), len(R.Marshal()))
}

func TestSign(t *testing.T) {
	// curve := elliptic.P256()
	curve := btcec.S256()
	fullTest(t, curve)
	// sizeTest(t, curve)
}

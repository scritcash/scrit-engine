// Package blind implements blind signatures over go/crypto/elliptic curves.
package blind

import (
	"crypto/elliptic"
	"errors"
	"io"
	"math/big"
)

var (
	zero = big.NewInt(0)
	one  = big.NewInt(1)
)

var (
	// ErrInvalidRequest is returned when a blind signature request contains dangerous values.
	ErrInvalidRequest = errors.New("blind: Invalid signing request")
)

// Signer is a signer.
type Signer struct {
	kp           *KeyPair // Long term keypair.
	randomSource io.Reader
}

// NewSigner creates a new signer.
func NewSigner(curve elliptic.Curve, randomSource io.Reader) (*Signer, error) {
	ccurve := NewCurve(curve)
	kp, err := ccurve.GenerateKey(randomSource)
	if err != nil {
		return nil, err
	}
	return &Signer{
		kp:           kp,
		randomSource: randomSource,
	}, nil
}

// NewSignerFromPrivateKey creates a signer from a given private key.
func NewSignerFromPrivateKey(curve elliptic.Curve, randomSource io.Reader, privateKey []byte) *Signer {
	ccurve := NewCurve(curve)
	return &Signer{
		kp:           UnmarshalKeyPair(ccurve, privateKey),
		randomSource: randomSource,
	}
}

// NewSignerFromKeyPair creates a signer from a keypair.
func NewSignerFromKeyPair(randomSource io.Reader, keypair *KeyPair) *Signer {
	return &Signer{
		kp:           keypair,
		randomSource: randomSource,
	}
}

// Private returns the marshalled private key.
func (self *Signer) Private() []byte {
	return self.kp.Marshal()
}

// Public returns the public key of the signer.
func (self *Signer) Public() *Point {
	return self.kp.Public
}

// test a skalar for dangerous values.
func validateSkalar(i *Skalar) bool {
	if (*big.Int)(i).Cmp(one) == 0 || (*big.Int)(i).Cmp(zero) == 0 {
		return false
	}
	return true
}

// test multiple skalars for dangerous values.
func validateSkalarMult(i ...*Skalar) bool {
	for _, j := range i {
		if !validateSkalar(j) {
			return false
		}
	}
	return true
}

// SignatureParam returns the per-signature parameters. Q is public, k is secret.
func (self *Signer) SignatureParams() (Q *Point, k *Skalar, err error) {
	for {
		kQ, err1 := self.kp.Public.curve.GenerateKey(self.randomSource) // Per signature keypair
		if err1 != nil {
			return nil, nil, err1
		}
		r1 := kQ.Public.ExtractR()
		if validateSkalar(r1) {
			return kQ.Public, kQ.Secret, nil
		}
	}
}

// Sign a signature request.
func (self *Signer) Sign(k *Skalar, msgBlinded *Skalar) (sBlind *Skalar, err error) {
	kQ := UnmarshalKeyPairFromSkalar(self.kp.Public.curve, k)
	r1 := kQ.Public.ExtractR()
	t1 := Multiply(self.kp.Secret, r1)
	t2 := Multiply(kQ.Secret, msgBlinded)
	res := self.kp.Public.curve.AddMod(
		t1,
		t2,
	)
	if !validateSkalarMult(res, t1, t2, self.kp.Secret, r1, kQ.Secret, msgBlinded) {
		return nil, ErrInvalidRequest
	}
	return res, nil
}

// BlindSignRequest blinds a message for signature.
func BlindSignRequest(curve elliptic.Curve, randomSource io.Reader, Q *Point, msgHash []byte) (signRequest *Skalar, m, n []byte, err error) {
	ccurve := NewCurve(curve)
	mF, err := ccurve.GenerateKey(randomSource)
	if err != nil {
		return nil, nil, nil, err
	}
	nG, err := ccurve.GenerateKey(randomSource)
	if err != nil {
		return nil, nil, nil, err
	}
	msg := ccurve.Skalar(msgHash)
	r1 := Q.ExtractR()
	r := nG.Public.Add(Q.ScalarMult(mF.Secret))
	r2 := r.ExtractR()
	r2i := ccurve.ModInverse(r2)

	msgb := ccurve.MulMod(mF.Secret, msg, r1, r2i)
	return msgb, mF.Marshal(), nG.Marshal(), nil
}

// UnblindSignature unblinds a blind signature.
func UnblindSignature(curve elliptic.Curve, Q *Point, msgHash []byte, blindSignature *Skalar, m, n []byte) (s *Skalar, R *Point) {
	ccurve := NewCurve(curve)
	msg := ccurve.Skalar(msgHash)
	r1 := Q.ExtractR()
	r1i := ccurve.ModInverse(r1)

	nG := UnmarshalKeyPair(ccurve, n)
	r := nG.Public.Add(Q.ScalarMult((*Skalar)(new(big.Int).SetBytes(m))))
	r2 := r.ExtractR()

	s = ccurve.AddMod(
		Multiply(blindSignature, r2, r1i),
		Multiply(nG.Secret, msg),
	)
	return s, r
}

// VerifySignature verifies a signature.
func VerifySignature(curve elliptic.Curve, signerPublicKey *Point, msgHash []byte, s *Skalar, R *Point) bool {
	ccurve := NewCurve(curve)
	msg := ccurve.Skalar(msgHash)
	r2 := R.ExtractR()
	lh := ccurve.ScalarBaseMult(s)
	rh := signerPublicKey.ScalarMult(r2).Add(R.ScalarMult(msg))
	return lh.Equal(rh)
}

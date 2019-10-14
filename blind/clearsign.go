package blind

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"math/big"
)

var RandomSource = rand.Reader

type ecdsaSignature struct {
	R, S *big.Int
}

// ECDSASign produces an ECDSA signature from the signer. Hashing is done internally.
func (self *Signer) ECDSASign(msg []byte) (sig []byte, err error) {
	priv := self.kp.ToECDSAPrivateKey()
	digest := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(RandomSource, priv, digest[:])
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(ecdsaSignature{r, s})
}

// ECDSAVerify verifies a signature.
func (self *Point) ECDSAVerify(msg []byte, sig []byte) bool {
	sigU := new(ecdsaSignature)
	_, err := asn1.Unmarshal(sig, sigU)
	if err != nil {
		return false
	}
	pub := self.ToECDSAPublicKey()
	digest := sha256.Sum256(msg)
	return ecdsa.Verify(pub, digest[:], sigU.R, sigU.S)
}

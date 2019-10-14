package blind

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"io"
	"math/big"

	"github.com/fd/eccp"
)

// Skalar is a (positive) integer.
type Skalar big.Int

// Marshal a skalar.
func (self *Skalar) Marshal() []byte {
	return (*big.Int)(self).Bytes()
}

// UnmarshalSkalar unmarshals a skalar.
func UnmarshalSkalar(d []byte) *Skalar {
	return (*Skalar)(new(big.Int).SetBytes(d))
}

// Point is a point on a curve.
type Point struct {
	curve *Curve
	X, Y  *Skalar
}

func (self *Point) Cmp(p *Point) bool {
	if self == nil || p == nil {
		return false
	}
	if (*big.Int)(self.X).Cmp((*big.Int)(p.X)) != 0 {
		return false
	}
	if (*big.Int)(self.Y).Cmp((*big.Int)(p.Y)) != 0 {
		return false
	}
	return true
}

// ToECDSAPublicKey converts a Point to an ecdsa.PublicKey that can be used by the standard library.
func (self *Point) ToECDSAPublicKey() *ecdsa.PublicKey {
	pk := new(ecdsa.PublicKey)
	pk.X = (*big.Int)(self.X)
	pk.Y = (*big.Int)(self.Y)
	pk.Curve = self.curve.curve
	return pk
}

// Marshal the point.
func (self *Point) Marshal() []byte {
	return eccp.Marshal(self.curve.curve, (*big.Int)(self.X), (*big.Int)(self.Y))
}

func (self *Point) Hex() string {
	return hex.EncodeToString(self.Marshal())
}

// UnmarshalPoint unmarshals a point marshaled by Point.Marshal
func UnmarshalPoint(curve *Curve, d []byte) *Point {
	x, y := eccp.Unmarshal(curve.curve, d)
	p := curve.Point()
	p.X, p.Y = (*Skalar)(x), (*Skalar)(y)
	return p
}

// Extract R: X mod p.
func (self *Point) ExtractR() *Skalar {
	return (*Skalar)(Mod(self.X, (*Skalar)(self.curve.params.N)))
}

// Add p to self and return a new Point as result.
func (self *Point) Add(p *Point) *Point {
	np := self.curve.Point()
	x, y := self.curve.curve.Add((*big.Int)(self.X), (*big.Int)(self.Y), (*big.Int)(p.X), (*big.Int)(p.Y))
	np.X, np.Y = (*Skalar)(x), (*Skalar)(y)
	return np
}

func (self *Point) ScalarMult(s *Skalar) *Point {
	np := self.curve.Point()
	x, y := self.curve.curve.ScalarMult((*big.Int)(self.X), (*big.Int)(self.Y), (*big.Int)(s).Bytes())
	np.X, np.Y = (*Skalar)(x), (*Skalar)(y)
	return np
}

// Equal returns true if p is equal, false otherwise.
func (self *Point) Equal(p *Point) bool {
	var x, y bool
	if ((*big.Int)(self.X)).Cmp((*big.Int)(p.X)) == 0 {
		x = true
	}
	if ((*big.Int)(self.Y)).Cmp((*big.Int)(p.Y)) == 0 {
		y = true
	}
	return x && y
}

// KeyPair contains public and private key on a curve.
type KeyPair struct {
	Public *Point
	Secret *Skalar
}

// ToECDSAPrivateKey converts a keypair to an ecdsa.PrivateKey that can be used by the standard library.
func (self *KeyPair) ToECDSAPrivateKey() *ecdsa.PrivateKey {
	pk := new(ecdsa.PrivateKey)
	pk.D = (*big.Int)(self.Secret)
	pk.PublicKey.X = (*big.Int)(self.Public.X)
	pk.PublicKey.Y = (*big.Int)(self.Public.Y)
	pk.PublicKey.Curve = self.Public.curve.curve
	return pk
}

// Marshal a keypair (only secret key is included).
func (self *KeyPair) Marshal() []byte {
	return (*big.Int)(self.Secret).Bytes()
}

// UnmarshalKeyPair unmarshales a keypair marshaled with KeyPair.Marshal.
func UnmarshalKeyPair(curve *Curve, d []byte) *KeyPair {
	nkp := &KeyPair{
		Secret: (*Skalar)(new(big.Int).SetBytes(d)),
	}
	nkp.Public = curve.ScalarBaseMult(nkp.Secret)
	return nkp
}

// UnmarshalKeyPairFromSkalar unmarshales a keypair from secret skalar.
func UnmarshalKeyPairFromSkalar(curve *Curve, d *Skalar) *KeyPair {
	nkp := &KeyPair{
		Secret: d,
	}
	nkp.Public = curve.ScalarBaseMult(nkp.Secret)
	return nkp
}

// Curve embeds a curve.
type Curve struct {
	curve  elliptic.Curve
	params *elliptic.CurveParams
}

// NewCurve returns a new curve.
func NewCurve(curve elliptic.Curve) *Curve {
	return &Curve{
		curve:  curve,
		params: curve.Params(),
	}
}

// GenerateKey generates a keypair on the curve.
func (self *Curve) GenerateKey(randomSource io.Reader) (*KeyPair, error) {
	a, x, y, err := elliptic.GenerateKey(self.curve, randomSource)
	if err != nil {
		return nil, err
	}
	kp := &KeyPair{
		Public: self.Point(),
	}
	kp.Public.X, kp.Public.Y = (*Skalar)(x), (*Skalar)(y)
	kp.Secret = (*Skalar)(new(big.Int).SetBytes(a))
	return kp, nil
}

// Return a new point, X and Y are nil.
func (self *Curve) Point() *Point {
	return &Point{
		curve: self,
	}
}

// Return the given bigendian byte slice int as skalar for the curve.
func (self *Curve) Skalar(b []byte) *Skalar {
	return (*Skalar)(new(big.Int).Mod(
		new(big.Int).SetBytes(b),
		self.params.N))
}

// MulMod : Multiply and modulus
func (self *Curve) MulMod(f ...*Skalar) *Skalar {
	return MulMod(self.params.N, f...)
}

// AddMod : Addition and modulus
func (self *Curve) AddMod(f ...*Skalar) *Skalar {
	return AddMod((*Skalar)(self.params.N), f...)
}

// ModInverse : Modular inverse
func (self *Curve) ModInverse(a *Skalar) *Skalar {
	return (*Skalar)(new(big.Int).ModInverse((*big.Int)(a), self.params.N))
}

// Multiply basepoint by skalar.
func (self *Curve) ScalarBaseMult(s *Skalar) *Point {
	np := self.Point()
	x, y := self.curve.ScalarBaseMult((*big.Int)(s).Bytes())
	np.X, np.Y = (*Skalar)(x), (*Skalar)(y)
	return np
}

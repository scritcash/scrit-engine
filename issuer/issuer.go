package issuer

import (
	"crypto/rand"
	"errors"
	"scrit/blind"
	"scrit/keydir"
	"scrit/types"
	"time"

	"golang.org/x/crypto/ed25519"
)

var (
	ErrWrongBlindSuite = errors.New("scrit/issuer: Wrong blinding suite in parameters.")
)

var RandomSource = rand.Reader

var timeNow = func() uint64 { return uint64(time.Now().Unix()) }

type IssuerOptions struct {
	KnownIssuers  []ed25519.PublicKey
	BlindSuite    types.BlindSuite
	ValidDuration uint64 // Number of seconds a signing key stays valid
	KeyManager    types.KeyManager
	KeyPublisher  KeyPublisher
}

type Issuer struct {
	publicKey      ed25519.PublicKey  // Public Key of the issuer
	PrivateKey     ed25519.PrivateKey // Private Key of the issuer
	curve          *blind.Curve
	BlindSuite     types.BlindSuite
	ParamGenerator *blind.Signer
	Signers        *keydir.Signers
	KeyRing        *PrivateKeyRing
	KeyManager     types.KeyManager
	KeyPublisher   KeyPublisher
}

// NewIssuer returns a new issuer.
func NewIssuer(options *IssuerOptions) (*Issuer, error) {
	_, privKey, err := ed25519.GenerateKey(RandomSource)
	if err != nil {
		panic(err)
	}
	return NewIssuerFromPrivateKey(privKey, options)
}

func (self *Issuer) PublicKey() ed25519.PublicKey {
	return self.publicKey
}

func ed25519PublicKey(privateKey ed25519.PrivateKey) ed25519.PublicKey {
	return privateKey.Public().(ed25519.PublicKey)
}

// NewIssuerFromPrivateKey returns a new issuer from a private key.
func NewIssuerFromPrivateKey(privateKey ed25519.PrivateKey, options *IssuerOptions) (*Issuer, error) {
	var err error
	issuer := new(Issuer)
	issuer.PrivateKey = privateKey
	issuer.publicKey = ed25519PublicKey(privateKey)
	issuer.BlindSuite = options.BlindSuite
	issuer.Signers = keydir.NewSigners(options.KnownIssuers)
	issuer.curve = blind.NewCurve(options.BlindSuite.Curve())
	issuer.KeyRing = NewPrivateKeyRing(options)
	issuer.KeyManager = options.KeyManager
	issuer.KeyPublisher = options.KeyPublisher
	issuer.ParamGenerator, err = blind.NewSigner(options.BlindSuite.Curve(), RandomSource)
	if err != nil {
		return nil, err
	}
	return issuer, err
}

// GetParams returns blinding parameters for the issuer.
func (self *Issuer) GetParams() (params []byte, Q *blind.Point, k *blind.Skalar, err error) {
	q, k, err := self.ParamGenerator.SignatureParams()
	if err != nil {
		return nil, nil, nil, err
	}
	params, err = self.BlindSuite.MarshalServerParams(q, k, self.KeyManager)
	return params, q, k, err
}

func (self *Issuer) DecryptParams(params []byte) (k *blind.Skalar, err error) {
	k, suite, err := types.UnmarshalMyServerParams(params, self.KeyManager)
	if err != nil {
		return nil, err
	}
	if suite.CurveID != self.BlindSuite.CurveID {
		return nil, ErrWrongBlindSuite
	}
	return k, nil
}

// SignSigner is called on newly created DBC signers to provide a signed certificate to other parties.
func (self *Issuer) signSigner(pk *PrivateKey) ([]byte, error) {
	self.BlindSuite.MarshalPubKey(pk.Signer.Public())
	out := &keydir.DBCCert{
		Subject: &keydir.DBCCertSubject{
			IssuerIdentity: self.publicKey,
			DBCSigKey:      self.BlindSuite.MarshalPubKey(pk.Signer.Public()),
			Currency:       string(pk.Currency),
			Value:          int64(pk.Value),
			ValidFrom:      pk.ValidFrom,
			ValidTo:        pk.ValidTo,
		},
	}
	marshalled, err := marshalDBCCertSubject(out.Subject)
	if err != nil {
		return nil, err
	}
	out.IssuerSignature = ed25519.Sign(self.PrivateKey, marshalled)
	sig, err := pk.Signer.ECDSASign(marshalled)
	if err != nil {
		return nil, err
	}
	out.DBCSignature = sig
	return marshalDBCCert(out)
}

// ToDo: Verification keys

// List of known other issuers:
//    - List of signer public keys, including self.

// Own:
// Currency, value, validfrom/to, signature publickey, signature privatekey

// 1.) Import known issuers
// 2.) Import known certs
// 3.) Set own keys

// DBC: Check Currency, Check Value, continue...

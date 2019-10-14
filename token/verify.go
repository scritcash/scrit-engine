package token

import (
	"bytes"
	"errors"
	"scrit/blind"
	"scrit/keydir"
	"scrit/types"

	"golang.org/x/crypto/ed25519"
)

var (
	ErrMixedValues        = errors.New("scrit/token: Mixed values in signatures")
	ErrUnSigned           = errors.New("scrit/token: Token is not signed")
	ErrNotVerified        = errors.New("scrit/token: Token is not verified")
	ErrIssuerNotFound     = errors.New("scrit/token: Issuer not found")
	ErrMissingValue       = errors.New("scrit/token: Transaction request too much value")
	ErrCorruptTransaction = errors.New("scrit/token: Corrupt transaction")
	ErrUnbalanced         = errors.New("scrit/token: Unbalanced transaction")
)

func (self *TokenWithSignatures) Signer() []byte {
	return self.Token.Signer()
}

// Describe may only be called on verified tokens.
func (self *TokenWithSignatures) Describe() (currency keydir.Currency, value keydir.Value, numSigners int, err error) {
	if self.verified == false {
		return "", 0, 0, ErrNotVerified
	}
	return self.currency, self.value, len(self.Signatures), nil
}

func (self *TokenWithSignatures) Issuers() []ed25519.PublicKey {
	return self.issuers
}

type verifiedSignature struct {
	signer    ed25519.PublicKey
	signature *TokenSignature
}

// VerifyToken verifies the token signatures and returns a verified token, or error.
func (self *TokenWithSignatures) VerifyToken(signers *keydir.Signers) (*TokenWithSignatures, error) {
	var Currency keydir.Currency
	var Value keydir.Value
	verifiedSignatures := make(map[keydir.PublicKeyHex]verifiedSignature)
	tokenHash, err := self.Token.SHA256()
	if err != nil {
		return nil, err
	}
	for _, sig := range self.Signatures {
		keyHex := keydir.PublicKeyHex(sig.PubKey.Hex())
		suite, err := types.New(sig.BlindSuite)
		if err != nil {
			continue
		}
		if !blind.VerifySignature(suite.Curve(), sig.PubKey, tokenHash, sig.S, sig.R) {
			continue
		}
		signer, ok := signers.Signer(keyHex)
		if !ok {
			continue
		}
		if Currency == "" {
			Currency = signer.Currency
		}
		if Value == 0 {
			Value = signer.Value
		}
		if Currency != signer.Currency || Value != signer.Value {
			return nil, ErrMixedValues
		}
		verifiedSignatures[keyHex] = verifiedSignature{
			signer:    signer.IssuerIdentity,
			signature: sig.Copy(),
		}
	}
	if len(verifiedSignatures) == 0 {
		return nil, ErrUnSigned
	}
	ret := &TokenWithSignatures{
		Token:      self.Token.Copy(),
		Signatures: make([]TokenSignature, 0, len(verifiedSignatures)),
		issuers:    make([]ed25519.PublicKey, 0, len(verifiedSignatures)),
		verified:   true,
		currency:   Currency,
		value:      Value,
	}
	for _, sig := range verifiedSignatures {
		ret.Signatures = append(ret.Signatures, *sig.signature)
		ret.issuers = append(ret.issuers, sig.signer)
	}
	return ret, nil
}

// Filter token so that only necessary signatures are left. Returns error if not found.
func (self *TokenWithSignatures) Filter(issuer ed25519.PublicKey) (*TokenWithSignatures, error) {
	if self.verified == false {
		return nil, ErrNotVerified
	}
	out := &TokenWithSignatures{
		Token: self.Token,
	}
	for n, issuesig := range self.issuers {
		if bytes.Equal(issuer, issuesig) {
			out.Signatures = []TokenSignature{self.Signatures[n]}
			return out, nil
		}
	}
	return nil, ErrIssuerNotFound
}

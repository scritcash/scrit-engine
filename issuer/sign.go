package issuer

import (
	"errors"
	"scrit/blind"
	"scrit/keydir"
	"scrit/token"
	"scrit/types"
)

var (
	ErrCurveMismatch = errors.New("scrit/issuer: CurveID mismatch")
)

// Issue issues a new DBC with given currency and value. It is very expensive since it simulates
// the full client -> issuer communication including serialization/marshalling and verification.
func (self *Issuer) Issue(tokenTemplate *token.Token, currency keydir.Currency, value keydir.Value) (serializedToken []byte, err error) {
	if tokenTemplate == nil {
		tokenTemplate = &token.Token{
			Type: token.TNoOwner,
		}
	}
	tokenHash, err := tokenTemplate.SHA256()
	if err != nil {
		return nil, err
	}
	// tokenHash := []byte("TestValue")
	params, _, _, err := self.GetParams()
	if err != nil {
		return nil, err
	}
	blindParam, suite, err := types.UnmarshalServerParams(params)
	if err != nil {
		return nil, err
	}
	signRequest, m, n, err := blind.BlindSignRequest(suite.Curve(), RandomSource, blindParam, tokenHash)
	if err != nil {
		return nil, err
	}
	public, private := suite.MarshalSignatureRequest(signRequest, m, n, blindParam)
	k, _, err := types.UnmarshalMyServerParams(params, self.KeyManager)
	if err != nil {
		return nil, err
	}
	_ = public
	blindsig, err := self.Sign(currency, value, signRequest, k)
	if err != nil {
		return nil, err
	}
	bSig, pubKey, suiteX, err := types.UnmarshalBlindSignature(blindsig)
	if err != nil {
		return nil, err
	}
	if suite.CurveID != suiteX.CurveID {
		return nil, ErrCurveMismatch
	}
	M, N, blindParam2, suiteX, err := types.UnmarshalSignatureRequestPrivate(private)
	if err != nil {
		return nil, err
	}
	if suite.CurveID != suiteX.CurveID {
		return nil, ErrCurveMismatch
	}
	s, r := blind.UnblindSignature(suiteX.Curve(), blindParam2, tokenHash, bSig, M, N)
	finalToken := &token.TokenWithSignatures{
		Token: tokenTemplate,
		Signatures: []token.TokenSignature{
			token.TokenSignature{
				BlindSuite: suite.CurveID,
				PubKey:     pubKey,
				S:          s,
				R:          r,
			},
		},
	}
	finalTokenSerialized, err := finalToken.Marshal()
	if err != nil {
		return nil, err
	}
	finalToken2, err := new(token.TokenWithSignatures).Unmarshal(finalTokenSerialized)
	if err != nil {
		return nil, err
	}
	ok := blind.VerifySignature(suite.Curve(), finalToken2.Signatures[0].PubKey, tokenHash, finalToken2.Signatures[0].S, finalToken2.Signatures[0].R)
	if !ok {
		return nil, errors.New("Implementation error. Not verified.")
	}
	return finalTokenSerialized, nil
}

// Verify the signature(s) of a DBC.
func (self *Issuer) Verify() {}

// Sign a blind signing request. Does not do any parameter spend checks!
func (self *Issuer) Sign(currency keydir.Currency, value keydir.Value, signatureRequest *blind.Skalar, blindParamK *blind.Skalar) (blindSignature []byte, err error) {
	signerPK, isNew, err := self.KeyRing.GetSignerByValue(currency, value)
	if err != nil {
		return nil, err
	}
	if isNew {
		signedSigner, err := self.signSigner(signerPK)
		if err != nil {
			return nil, err
		}
		if err = self.KeyPublisher.Publish(signedSigner); err != nil {
			return nil, err
		}
	}
	blindsig, err := signerPK.Signer.Sign(blindParamK, signatureRequest)
	if err != nil {
		return nil, err
	}
	return self.BlindSuite.MarshalBlindSignature(blindsig, signerPK.Signer.Public()), nil
}

package tests

import (
	"bytes"
	"crypto/rand"
	"errors"
	"scrit/issuer"
	"scrit/keydir"
	"scrit/token"
	"scrit/types"
	"testing"

	"golang.org/x/crypto/ed25519"
)

type testParamFactory struct {
	paramSources map[keydir.PublicKeyHex]*issuer.Issuer
}

func newTestParamFactory() *testParamFactory {
	return &testParamFactory{
		paramSources: make(map[keydir.PublicKeyHex]*issuer.Issuer),
	}
}

func (self *testParamFactory) Learn(issuer ed25519.PublicKey, source *issuer.Issuer) {
	self.paramSources[keydir.Ed25519PubKeyToHex(issuer)] = source
}

func (self *testParamFactory) FetchServerParam(signer ed25519.PublicKey) error {
	if _, ok := self.paramSources[keydir.Ed25519PubKeyToHex(signer)]; ok {
		return nil
	}
	return errors.New("Parameter source unknown")
}

func (self *testParamFactory) GetServerParam(signer ed25519.PublicKey) ([]byte, error) {
	if issuer, ok := self.paramSources[keydir.Ed25519PubKeyToHex(signer)]; ok {
		params, _, _, err := issuer.GetParams()
		return params, err
	}
	return nil, errors.New("Parameter source unknown")
}

type testKeyLearn struct {
	publish func([]byte)
}

func (self *testKeyLearn) Publish(serializedDBCCert []byte) error {
	if self.publish != nil {
		self.publish(serializedDBCCert)
	}
	return nil
}

type testKeyRing struct {
	privKey ed25519.PrivateKey
}

func (self *testKeyRing) FetchPrivateKey(publicKey []byte) error { return nil }
func (self *testKeyRing) PrivateKey(publicKey []byte) (ed25519.PrivateKey, error) {
	return self.privKey, nil
}

func TestKeyDir(t *testing.T) {
	var token1, token2, token3 []byte
	myPublicKey, myPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %s", err)
	}
	keyRing := &testKeyRing{
		privKey: myPrivateKey,
	}
	paramFactory := newTestParamFactory()
	tokenTemplate := &token.Token{
		Type:       token.TSingleOwner,
		FirstOwner: myPublicKey,
	}
	tokenTemplate.Validate()
	keyLearn := new(testKeyLearn)
	blindsuite := types.Nist256()
	options := &issuer.IssuerOptions{
		KnownIssuers:  nil,
		BlindSuite:    blindsuite,
		ValidDuration: 1000,
		KeyManager:    new(testKeyManager),
		KeyPublisher:  keyLearn,
	}
	issuer1, err := issuer.NewIssuer(options)
	if err != nil {
		t.Fatalf("NewIssuer: %s", err)
	}
	paramFactory.Learn(issuer1.PublicKey(), issuer1)
	issuer2, err := issuer.NewIssuer(options)
	if err != nil {
		t.Fatalf("NewIssuer: %s", err)
	}
	paramFactory.Learn(issuer2.PublicKey(), issuer2)
	issuer3, err := issuer.NewIssuer(options)
	if err != nil {
		t.Fatalf("NewIssuer: %s", err)
	}
	signers := keydir.NewSigners([]ed25519.PublicKey{issuer1.PublicKey(), issuer2.PublicKey()})
	keyLearn.publish = func(cert []byte) {
		if err := signers.Import(cert); err != nil {
			t.Errorf("Import of known signer: %s", err)
		}
	}
	if token1, err = issuer1.Issue(tokenTemplate, keydir.Currency("EUR"), keydir.Value(10)); err != nil {
		t.Errorf("Issue: %s", err)
	}
	if token2, err = issuer2.Issue(tokenTemplate, keydir.Currency("EUR"), keydir.Value(10)); err != nil {
		t.Errorf("Issue: %s", err)
	}
	keyLearn.publish = func(cert []byte) {
		if signers.Import(cert) == nil {
			t.Error("Import of unknown signer must fail")
		}
	}
	if token3, err = issuer3.Issue(tokenTemplate, keydir.Currency("EUR"), keydir.Value(10)); err != nil {
		t.Errorf("Issue: %s", err)
	}
	keyLearn.publish = nil

	tokenSig1, err := new(token.TokenWithSignatures).Unmarshal(token1)
	if err != nil {
		t.Errorf("Token Unmarshal: %s", err)
	}
	tokenSigner, ok := signers.Signer(keydir.PublicKeyHex(tokenSig1.Signatures[0].PubKey.Hex()))
	if !ok {
		t.Error("Signer not found")
	}
	if tokenSigner.Value != 10 {
		t.Error("Incorrect value")
	}
	if tokenSigner.Currency != "EUR" {
		t.Error("Incorrect currency")
	}
	if !bytes.Equal(issuer1.PublicKey(), tokenSigner.IssuerIdentity) {
		t.Error("Wrong issuer")
	}
	tokenSig2, _ := new(token.TokenWithSignatures).Unmarshal(token2)
	tokenSig1.Signatures = append(tokenSig1.Signatures, tokenSig2.Signatures[0])
	tokenSig3, _ := new(token.TokenWithSignatures).Unmarshal(token3)
	tokenSig1.Signatures = append(tokenSig1.Signatures, tokenSig3.Signatures[0])

	verifiedToken, err := tokenSig1.VerifyToken(signers)
	if err != nil {
		t.Errorf("VerifyToken: %s", err)
	}
	currency, value, signerCount, err := verifiedToken.Describe()
	if err != nil {
		t.Errorf("Describe: %s", err)
	}
	if currency != "EUR" {
		t.Error("Wrong currency")
	}
	if value != 10 {
		t.Error("Wrong value")
	}
	if signerCount != 2 {
		t.Error("Wrong signer count")
	}
	trans := token.NewTransaction(keyRing, paramFactory, []ed25519.PublicKey{issuer1.PublicKey(), issuer2.PublicKey()})
	err = trans.AddInput(verifiedToken)
	if err != nil {
		t.Fatalf("AddInput: %s", err)
	}
	newToken := &token.Token{
		Type: token.TNoOwner,
	}
	err = newToken.Validate()
	if err != nil {
		t.Fatalf("Validate: %s", err)
	}
	err = trans.AddOutput(3, newToken)
	if err != nil {
		t.Fatalf("AddOutput: %s", err)
	}
	newToken = &token.Token{
		Type: token.TNoOwner,
	}
	err = newToken.Validate()
	if err != nil {
		t.Fatalf("Validate: %s", err)
	}
	trans.Balance(newToken)
	binaryTransactions, err := trans.Transact()
	if err != nil {
		t.Fatalf("Transact: %s", err)
	}
	for _, tr := range binaryTransactions {
		verifiedTr, err := tr.Transaction.Verify(signers)
		if err != nil {
			t.Errorf("Transaction verify: %s", err)
		}
		_ = verifiedTr
		// spew.Dump(verifiedTr)
	}
}

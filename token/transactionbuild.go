package token

import (
	"crypto/sha256"
	"encoding/asn1"
	"scrit/blind"
	"scrit/types"

	"golang.org/x/crypto/ed25519"
)

type IssuerTransaction struct {
	Issuer          ed25519.PublicKey // Issuer for which to prepare transaction
	Expects         [][]byte          // Data required for unblinding
	Transaction     BinaryTransaction // Transaction data
	TransactionHash []byte
}

func (self *Transaction) newIssuertransaction(issuer ed25519.PublicKey) *IssuerTransaction {
	r := &IssuerTransaction{
		Issuer:      issuer,
		Transaction: BinaryTransaction{},
	}
	r.Transaction.InputTokens = self.inputTokensSerialized
	return r
}

func (self *Transaction) signatureRequests(issuer ed25519.PublicKey, issuerTransaction *IssuerTransaction) error {
	// Generate signature requests:
	// - Get server params
	// - Generate Blind signature request
	for tokenPos, ot := range self.outputValues {
		otT := BinaryOutput{Value: int(ot)}
		paramS, err := self.paramFactory.GetServerParam(issuer)
		if err != nil {
			return err
		}
		otT.ServerBlindingParameter = paramS
		Q, suite, err := types.UnmarshalServerParams(paramS)
		if err != nil {
			return err
		}
		signRequest, m, n, err := blind.BlindSignRequest(suite.Curve(), randomSource, Q, self.outputTokenHashes[tokenPos])
		if err != nil {
			return err
		}
		toServer, private := suite.MarshalSignatureRequest(signRequest, m, n, Q)
		otT.BlindSignatureRequest = toServer
		issuerTransaction.Transaction.Outputs = append(issuerTransaction.Transaction.Outputs, otT)
		issuerTransaction.Expects = append(issuerTransaction.Expects, private)
	}
	return nil
}

func (self *Transaction) filterSignatures(issuer ed25519.PublicKey, issuerTransaction *IssuerTransaction) error {
	//  - Add only necessary signatures to transaction
	//		- If issuer is not part of token signatures, ALL, otherwise just himself.
	for _, it := range self.inputTokens {
		var sigs []byte
		var err error
		itF, err := it.Filter(issuer)
		if err != nil {
			// serialize it.Signatures
			sigs, err = it.MarshalSignatures()
		} else {
			// serialize itF.Signatures
			sigs, err = itF.MarshalSignatures()
		}
		if err != nil {
			return err
		}
		issuerTransaction.Transaction.TokenSignatures = append(issuerTransaction.Transaction.TokenSignatures, sigs)
	}
	return nil
}

func (self *Transaction) signTokens(issuer ed25519.PublicKey, issuerTransaction *IssuerTransaction) error {
	//  - Sign: inputToken, TXHash
	//  - Add signature to transaction
	for tokenPos, it := range self.inputTokens {
		transSig := []byte("n/a")
		owner := it.Signer()
		if owner != nil {
			privKey, err := self.keyRing.PrivateKey(owner)
			if err != nil {
				return err
			}
			transSig = ed25519.Sign(privKey, calcHMAC(self.inputTokensHashes[tokenPos], issuerTransaction.TransactionHash))
		}
		issuerTransaction.Transaction.OwnerSignatures = append(issuerTransaction.Transaction.OwnerSignatures, transSig)
	}
	return nil
}

func calcOutputHash(outputs []BinaryOutput) ([]byte, error) {
	d, err := asn1.Marshal(outputs)
	if err != nil {
		return nil, err
	}
	oHash := sha256.Sum256(d)
	return oHash[:], nil
}

func (self *Transaction) transactionFor(issuer ed25519.PublicKey) (*IssuerTransaction, error) {
	if len(self.outputTokens) != len(self.outputValues) {
		return nil, ErrCorruptTransaction
	}
	issuerTransaction := self.newIssuertransaction(issuer)
	if err := self.signatureRequests(issuer, issuerTransaction); err != nil {
		return nil, err
	}
	if err := self.filterSignatures(issuer, issuerTransaction); err != nil {
		return nil, err
	}
	// Calculate TXHash:=hmac(inputtokens, outputvalues)
	oHash, err := calcOutputHash(issuerTransaction.Transaction.Outputs)
	if err != nil {
		return nil, err
	}
	issuerTransaction.TransactionHash = calcHMAC(self.tokenListHash, oHash)
	if err := self.signTokens(issuer, issuerTransaction); err != nil {
		return nil, err
	}
	return issuerTransaction, nil
}

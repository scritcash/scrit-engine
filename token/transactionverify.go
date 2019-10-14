package token

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"scrit/keydir"

	"golang.org/x/crypto/ed25519"
)

var (
	ErrSignatureNotEmpty = errors.New("scrit/token: Signature should be empty")
	ErrSignatureWrong    = errors.New("scrit/token: Signature wrong")
)

type TransactionProof struct {
	TokenHash       []byte
	TransactionHash []byte
	Signature       []byte
}

func (self *TransactionProof) Verify(owner []byte) bool {
	sigInput := calcHMAC(self.TokenHash, self.TransactionHash)
	return ed25519.Verify(owner, sigInput, self.Signature)
}

func (self *TransactionProof) Marshal() ([]byte, error) {
	return asn1.Marshal(*self)
}

func (self *TransactionProof) Unmarshal(d []byte) (*TransactionProof, error) {
	ret := new(TransactionProof)
	_, err := asn1.Unmarshal(d, ret)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

type VerifiedTransaction struct {
	InputTokens       []TokenWithSignatures // Decoded and re-assembled tokens to be spent
	Outputs           []BinaryOutput        // Outputs
	TransactionProofs [][]byte              // Transaction proof, per InputToken

	inputTokensSerialized [][]byte
	inputTokensHashes     [][]byte
	tokenListHash         []byte
	transactionHash       []byte
	currency              keydir.Currency
	value                 keydir.Value
}

func (self *BinaryTransaction) Verify(signers *keydir.Signers) (*VerifiedTransaction, error) {
	var err error
	transSig := []byte("n/a")
	ret := new(VerifiedTransaction)
	for tokenPos, tM := range self.InputTokens {
		nt, err := new(Token).Unmarshal(tM)
		if err != nil {
			return nil, err
		}
		ns, err := new(TokenWithSignatures).UnmarshalSignatures(self.TokenSignatures[tokenPos])
		if err != nil {
			return nil, err
		}
		decodedToken := &TokenWithSignatures{
			Token:      nt,
			Signatures: ns,
		}
		tokenVerified, err := decodedToken.VerifyToken(signers)
		if err != nil {
			return nil, err
		}
		currency, value, _, err := tokenVerified.Describe()
		if err != nil {
			return nil, err
		}
		if ret.currency == "" {
			ret.currency = currency
		}
		if ret.currency != currency {
			return nil, ErrMixedValues
		}
		ret.value = ret.value + value
		ret.InputTokens = append(ret.InputTokens, *tokenVerified)
	}
	ret.inputTokensSerialized, ret.inputTokensHashes, ret.tokenListHash, err = calculateTokenHash(ret.InputTokens)
	if err != nil {
		return nil, err
	}
	oHash, err := calcOutputHash(self.Outputs)
	if err != nil {
		return nil, err
	}
	ret.transactionHash = calcHMAC(ret.tokenListHash, oHash)
	for tokenPos, t := range ret.InputTokens {
		proofM := []byte("n/a")
		owner := t.Signer()
		if owner == nil {
			if !bytes.Equal(transSig, self.OwnerSignatures[tokenPos]) {
				return nil, ErrSignatureNotEmpty
			}
		} else {
			proof := &TransactionProof{
				TokenHash:       ret.inputTokensHashes[tokenPos],
				TransactionHash: ret.transactionHash,
				Signature:       self.OwnerSignatures[tokenPos],
			}
			if !proof.Verify(owner) {
				return nil, ErrSignatureWrong
			}
			proofM, err = proof.Marshal()
			if err != nil {
				return nil, err
			}
		}
		ret.TransactionProofs = append(ret.TransactionProofs, proofM)
	}
	for _, op := range self.Outputs {
		ret.value = ret.value - keydir.Value(op.Value)
	}
	if ret.value != 0 {
		return nil, ErrUnbalanced
	}
	return ret, nil
}

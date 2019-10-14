package token

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"io"
	"scrit/blind"
	"scrit/keydir"
	"scrit/types"
	"time"

	"golang.org/x/crypto/ed25519"
)

var RandomSource = rand.Reader
var timeNow = func() uint64 { return uint64(time.Now().Unix()) }

var (
	ErrTokenFormat = errors.New("scrit/token: Token format error")
)

const (
	TNoOwner     = 0
	TSingleOwner = 1
	TSplitOwner  = 2
)

type Token struct {
	Random      []byte
	Type        int
	FirstOwner  []byte
	SecondOwner []byte
	CutOffTime  int64 // Unixtime to switch between first and second owner
}

func (self *Token) Copy() *Token {
	return &Token{
		Random:      self.Random,
		Type:        self.Type,
		FirstOwner:  self.FirstOwner,
		SecondOwner: self.SecondOwner,
		CutOffTime:  self.CutOffTime,
	}
}

type TokenSignature struct {
	BlindSuite byte
	PubKey     *blind.Point
	S          *blind.Skalar
	R          *blind.Point
}

func (self *TokenSignature) Copy() *TokenSignature {
	return &TokenSignature{
		BlindSuite: self.BlindSuite,
		PubKey:     self.PubKey,
		S:          self.S,
		R:          self.R,
	}
}

func (self *TokenSignature) Unmarshal(d []byte) (*TokenSignature, error) {
	pubkey, s, r, suite, err := types.UnmarshalSignature(d)
	if err != nil {
		return nil, err
	}
	return &TokenSignature{
		BlindSuite: suite.CurveID,
		PubKey:     pubkey,
		S:          s,
		R:          r,
	}, nil
}

func (self *TokenSignature) Marshal() ([]byte, error) {
	suite, err := types.New(self.BlindSuite)
	if err != nil {
		return nil, err
	}
	return suite.MarshalSignature(self.PubKey, self.S, self.R), nil
}

type TokenWithSignatures struct {
	Token      *Token
	Signatures []TokenSignature
	issuers    []ed25519.PublicKey
	verified   bool
	currency   keydir.Currency
	value      keydir.Value
}

type compressedTokenSig struct {
	Token      []byte
	Signatures [][]byte
}

func (self *TokenWithSignatures) Marshal() ([]byte, error) {
	var err error
	x := &compressedTokenSig{
		Signatures: make([][]byte, 0, len(self.Signatures)),
	}
	x.Token, err = self.Token.Marshal()
	if err != nil {
		return nil, err
	}
	for _, sig := range self.Signatures {
		sigM, err := sig.Marshal()
		if err != nil {
			return nil, err
		}
		x.Signatures = append(x.Signatures, sigM)
	}
	return asn1.Marshal(*x)
}

type tempSignatureList struct {
	Signatures [][]byte
}

func (self *TokenWithSignatures) MarshalSignatures() ([]byte, error) {
	tS := new(tempSignatureList)
	// d := make([][]byte, 0, len(self.Signatures))
	for _, sig := range self.Signatures {
		sigM, err := sig.Marshal()
		if err != nil {
			return nil, err
		}
		// d = append(d, sigM)
		tS.Signatures = append(tS.Signatures, sigM)
	}
	// return asn1.Marshal(d)
	return asn1.Marshal(*tS)
}

func (self *TokenWithSignatures) UnmarshalSignatures(b []byte) ([]TokenSignature, error) {
	tS := new(tempSignatureList)
	_, err := asn1.Unmarshal(b, tS)
	if err != nil {
		return nil, err
	}
	ret := make([]TokenSignature, 0, len(tS.Signatures))
	for _, mS := range tS.Signatures {
		sig, err := new(TokenSignature).Unmarshal(mS)
		if err != nil {
			return nil, err
		}
		ret = append(ret, *sig)
	}
	return ret, nil
}

func (self *TokenWithSignatures) Unmarshal(b []byte) (*TokenWithSignatures, error) {
	ttoken := new(Token)
	ssignature := new(TokenSignature)
	x := new(compressedTokenSig)
	_, err := asn1.Unmarshal(b, x)
	if err != nil {
		return nil, err
	}
	n := &TokenWithSignatures{
		Signatures: make([]TokenSignature, 0, len(x.Signatures)),
	}
	n.Token, err = ttoken.Unmarshal(x.Token)
	if err != nil {
		return nil, err
	}
	for _, sig := range x.Signatures {
		sigD, err := ssignature.Unmarshal(sig)
		if err != nil {
			return nil, err
		}
		n.Signatures = append(n.Signatures, *sigD)
	}
	return n, nil
}

func (self *Token) Signer() []byte {
	switch self.Type {
	case TNoOwner:
		return nil
	case TSingleOwner:
		return self.FirstOwner
	case TSplitOwner:
		if self.CutOffTime > int64(timeNow()) {
			return self.FirstOwner
		}
		return self.SecondOwner
	}
	return nil
}

func (self *Token) Validate() error {
	switch self.Type {
	case TNoOwner:
		if self.FirstOwner != nil || self.SecondOwner != nil || self.CutOffTime != 0 {
			return ErrTokenFormat
		}
	case TSingleOwner:
		if self.FirstOwner == nil || self.SecondOwner != nil || self.CutOffTime != 0 {
			return ErrTokenFormat
		}
	case TSplitOwner:
		if self.FirstOwner == nil || self.SecondOwner == nil || self.CutOffTime == 0 {
			return ErrTokenFormat
		}
	default:
		return ErrTokenFormat
	}
	if self.Random == nil {
		self.Random = make([]byte, 32)
		_, err := io.ReadFull(RandomSource, self.Random)
		if err != nil {
			return err
		}
	}
	return nil
}

func (self *Token) SHA256() ([]byte, error) {
	d, err := self.Marshal()
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(d)
	return h[:], nil
}

func (self *Token) Marshal() ([]byte, error) {
	err := self.Validate()
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(*self)
}

func (self *Token) Unmarshal(b []byte) (*Token, error) {
	n := new(Token)
	_, err := asn1.Unmarshal(b, n)
	if err != nil {
		return nil, err
	}
	switch n.Type {
	case TNoOwner:
		n.FirstOwner = nil
		n.SecondOwner = nil
		n.CutOffTime = 0
	case TSingleOwner:
		n.SecondOwner = nil
		n.CutOffTime = 0
	case TSplitOwner:
		break
	default:
		return nil, ErrTokenFormat
	}
	err = self.Validate()
	if err != nil {
		return nil, err
	}
	return n, nil
}

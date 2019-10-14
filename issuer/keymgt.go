package issuer

import (
	"errors"
	"scrit/blind"
	"scrit/keydir"
	"strconv"
	"sync"
)

var (
	ErrKeyNotFound = errors.New("scrit/issuer: Signer key not found")
)

type PrivateKey struct {
	Currency  keydir.Currency
	Value     keydir.Value
	Signer    *blind.Signer
	ValidFrom int64
	ValidTo   int64
}

type CurrencyValue string

func FormatCurrencyValue(c keydir.Currency, v keydir.Value) CurrencyValue {
	return CurrencyValue(string(c) + "_" + strconv.FormatUint(uint64(v), 16))
}

type PrivateKeyRing struct {
	ByValue map[CurrencyValue]*PrivateKey
	// ByKey   map[keydir.PublicKeyHex]*PrivateKey
	options *IssuerOptions
	mutex   *sync.Mutex
}

func NewPrivateKeyRing(options *IssuerOptions) *PrivateKeyRing {
	return &PrivateKeyRing{
		ByValue: make(map[CurrencyValue]*PrivateKey),
		// ByKey:   make(map[keydir.PublicKeyHex]*PrivateKey),
		options: options,
		mutex:   new(sync.Mutex),
	}
}

// func (self *PrivateKeyRing) GetSignerByKey(key keydir.PublicKeyHex) (*PrivateKey, error) {
// 	self.mutex.Lock()
// 	defer self.mutex.Unlock()
// 	if s, ok := self.ByKey[key]; ok {
// 		return s, nil
// 	}
// 	return nil, ErrKeyNotFound
// }

// GetSignerByValue returns a matching signer. If isNew is true, the returned key needs to be signed and published.
func (self *PrivateKeyRing) GetSignerByValue(c keydir.Currency, v keydir.Value) (signer *PrivateKey, isNew bool, err error) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	cv := FormatCurrencyValue(c, v)
	if s, ok := self.ByValue[cv]; ok {
		return s, false, nil
	}
	s, err := self.addKey(c, v)
	if err != nil {
		return nil, false, err
	}
	return s, true, nil
}

func (self *PrivateKeyRing) addKey(c keydir.Currency, v keydir.Value) (signer *PrivateKey, err error) {
	cv := FormatCurrencyValue(c, v)
	signerS, err := blind.NewSigner(self.options.BlindSuite.Curve(), RandomSource)
	if err != nil {
		return nil, err
	}
	signerKey := &PrivateKey{
		Currency:  c,
		Value:     v,
		Signer:    signerS,
		ValidFrom: int64(timeNow()),
		ValidTo:   int64(timeNow() + self.options.ValidDuration),
	}
	self.ByValue[cv] = signerKey
	return signerKey, nil
}

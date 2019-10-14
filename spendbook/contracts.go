package spendbook

import (
	"crypto/sha256"
	"time"
)

func makeKey(keyID []byte, entryType byte, uniqueKey []byte) []byte {
	key := make([]byte, 66)
	copy(key[0:33], keyID)
	key[34] = entryType
	keyHash := sha256.Sum256(uniqueKey)
	copy(key[35:65], keyHash[:])
	return key
}

func calcTTL(expireTime time.Time) time.Duration {
	d := expireTime.Sub(timeNowTime())
	if d <= 0 {
		d = 0
	}
	return d + SkewSafety
}

// SpendParamIfUnkown spends a blinding parameter. The pubKey is the MARSHALLED public key for which the parameter was generated,
// value is the secret k skalar of the blinding parameter.
// keyExpireTime is the time at which pubKey will expire and not be used for verification anymore.
func (self *Book) SpendParamIfUnknown(pubKey, value []byte, keyExpireTime time.Time) (storedValue []byte, err error) {
	key := makeKey(pubKey, TypeParam, value)
	ttl := calcTTL(keyExpireTime)
	return self.spendIfUnknown(key, value, ttl)
}

// IsParamSpent checks if a blinding parameter has been used. The pubKey is the MARSHALLED public key for which the parameter was generated,
// value is the secret k skalar of the blinding parameter.
func (self *Book) IsParamSpent(pubKey, value []byte) (storedValue []byte, spent bool) {
	key := makeKey(pubKey, TypeParam, value)
	return self.isSpent(key)
}

// SpendDBCIfUnkown spends a DBC. The pubKey is the MARSHALLED public key for which the parameter was generated,
// rValue is the signed value of the DBC. spendProof is the (client-) signed transaction proof.
// keyExpireTime is the time at which pubKey will expire and not be used for verification anymore.
func (self *Book) SpendDBCIfUnkown(pubKey, rValue, spendProof []byte, keyExpireTime time.Time) (storedValue []byte, err error) {
	key := makeKey(pubKey, TypeParam, rValue)
	ttl := calcTTL(keyExpireTime)
	return self.spendIfUnknown(key, spendProof, ttl)
}

// IsDBCSpent checks if a blinding parameter has been used. The pubKey is the MARSHALLED public key for which the parameter was generated,
// rValue is the signed value of the DBC.
func (self *Book) IsDBCSpent(pubKey, rValue []byte) (storedValue []byte, spent bool) {
	key := makeKey(pubKey, TypeParam, rValue)
	return self.isSpent(key)
}

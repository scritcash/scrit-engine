// Package keydir implements local key directory functions that allow looking up public keys and
// finding out their meaning for a DBC signature.
package keydir

import (
	"encoding/hex"
	"errors"
	"scrit/blind"
	"scrit/types"
	"time"

	"golang.org/x/crypto/ed25519"
)

var (
	timeNow = func() uint64 { return uint64(time.Now().Unix()) }
)

var (
	ErrExpired       = errors.New("scrit/keydir: DBC Cert expired")
	ErrUnknownIssuer = errors.New("scrit/keydir: Issuer unkown")
)

type Currency string
type Value uint64
type PublicKeyHex string

// DBCSigner describes the meaning of a key for DBC signatures.
type DBCSigner struct {
	Currency       Currency
	Value          Value
	ValidFrom      int64
	ValidTo        int64
	PublicKey      *blind.Point
	IssuerIdentity ed25519.PublicKey
	Self           bool // True if this is myself
}

// Signers contain a map of public key -> DBCSigner.
type Signers struct {
	signers      map[PublicKeyHex]*DBCSigner // Public Key pointing to signer
	knownIssuers map[PublicKeyHex]bool       // ed25519 identity keys that are known
}

func Ed25519PubKeyToHex(pubkey ed25519.PublicKey) PublicKeyHex {
	return PublicKeyHex(hex.EncodeToString(pubkey))
}

// NewSigners returns a new signer directory.
func NewSigners(knownSigners []ed25519.PublicKey) *Signers {
	s := &Signers{
		signers:      make(map[PublicKeyHex]*DBCSigner),
		knownIssuers: make(map[PublicKeyHex]bool),
	}
	for _, key := range knownSigners {
		s.knownIssuers[Ed25519PubKeyToHex(key)] = true
	}
	return s
}

func (self *Signers) CountIssuers() int {
	return len(self.knownIssuers)
}

func dbccertToDBCSigner(dbccert *DBCCert) (*DBCSigner, error) {
	pk, _, err := types.UnmarshalPubKey(dbccert.Subject.DBCSigKey)
	if err != nil {
		return nil, err
	}
	return &DBCSigner{
		Currency:       Currency(dbccert.Subject.Currency),
		Value:          Value(dbccert.Subject.Value),
		ValidFrom:      dbccert.Subject.ValidFrom,
		ValidTo:        dbccert.Subject.ValidTo,
		PublicKey:      pk,
		IssuerIdentity: dbccert.Subject.IssuerIdentity,
		Self:           false,
	}, nil
}

// KnownIssuer returns true if the public key provided belongs to a known issuer.
func (self *Signers) KnownIssuer(key ed25519.PublicKey) bool {
	if _, ok := self.knownIssuers[Ed25519PubKeyToHex(key)]; ok {
		return true
	}
	return false
}

// Import a serialized DBCCert, including verification.
func (self *Signers) Import(cert []byte) error {
	dbccert, err := UnmarshalDBCCert(cert)
	if err != nil {
		return err
	}
	if dbccert.Subject.ValidTo < int64(timeNow()) {
		return ErrExpired
	}
	if !self.KnownIssuer(dbccert.Subject.IssuerIdentity) {
		return ErrUnknownIssuer
	}
	s, err := dbccertToDBCSigner(dbccert)
	if err != nil {
		return err
	}
	self.signers[PublicKeyHex(s.PublicKey.Hex())] = s
	return nil
}

// SetSelf marks a signer als self-owned.
func (self Signers) SetSelf(pk PublicKeyHex) bool {
	r, ok := self.Signer(pk)
	if ok {
		r.Self = true
	}
	return ok
}

// Lookup returns a DBCSigner, if found. Will not return expired signers.
func (self Signers) Signer(pk PublicKeyHex) (*DBCSigner, bool) {
	if s, ok := self.signers[pk]; ok {
		if s.ValidTo < int64(timeNow()) {
			return nil, false
		}
		return s, ok
	}
	return nil, false
}

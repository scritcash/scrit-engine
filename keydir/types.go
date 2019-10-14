package keydir

import (
	"encoding/asn1"
	"errors"
	"scrit/types"

	"golang.org/x/crypto/ed25519"
)

var (
	ErrDBCSignature    = errors.New("scrit/types: DBC signer self-signature failed. This should be considered as an attack!")
	ErrIssuerSignature = errors.New("scrit/types: Issuer self-signature failed. This should be considered as an attack!")
)

// DBCCertSubject describes the contents of a DBCCert referring to meaning of signatures of a cert.
type DBCCertSubject struct {
	IssuerIdentity ed25519.PublicKey // ed25519 public key of the issuer
	DBCSigKey      []byte            // Serialized public key for this DBC
	Currency       string            // Currency code for this DBC
	Value          int64             // Value of this DBC
	ValidFrom      int64             // Unixtime of the first moment a DBC can be signed with this key.
	ValidTo        int64             // Unixtime of last moment the DBC is valid.
}

// DBCCert is a signing certificate issued by a signer.
type DBCCert struct {
	Subject         *DBCCertSubject
	DBCSignature    []byte // ecdsa signature by subject.DBCSigKey
	IssuerSignature []byte // ed25519 signature of issuer by subject.IssuerIdentity
}

type dbccert struct {
	Subject         []byte
	DBCSignature    []byte // ecdsa signature by subject.DBCSigKey
	IssuerSignature []byte // ed25519 signature of issuer by subject.IssuerIdentity
}

func unmarshalDBCCertSubject(d []byte) (*DBCCertSubject, error) {
	r := new(DBCCertSubject)
	_, err := asn1.Unmarshal(d, r)
	if err != nil {
		return nil, err
	}
	return r, nil
}

func UnmarshalDBCCert(d []byte) (*DBCCert, error) {
	r := new(dbccert)
	_, err := asn1.Unmarshal(d, r)
	if err != nil {
		return nil, err
	}
	q := &DBCCert{
		DBCSignature:    r.DBCSignature,
		IssuerSignature: r.IssuerSignature,
	}
	if q.Subject, err = unmarshalDBCCertSubject(r.Subject); err != nil {
		return nil, err
	}
	pubKey, _, err := types.UnmarshalPubKey(q.Subject.DBCSigKey)
	if err != nil {
		return nil, err
	}
	if ok := pubKey.ECDSAVerify(r.Subject, q.DBCSignature); !ok {
		return nil, ErrDBCSignature
	}
	if ok := ed25519.Verify(q.Subject.IssuerIdentity, r.Subject, q.IssuerSignature); !ok {
		return nil, ErrIssuerSignature
	}
	return q, nil
}

package issuer

import (
	"encoding/asn1"
	"scrit/keydir"
)

type KeyPublisher interface {
	Publish(serializedDBCCert []byte) error
}

type dbccert struct {
	Subject         []byte
	DBCSignature    []byte // ecdsa signature by subject.DBCSigKey
	IssuerSignature []byte // ed25519 signature of issuer by subject.IssuerIdentity
}

func marshalDBCCertSubject(cert *keydir.DBCCertSubject) ([]byte, error) {
	return asn1.Marshal(*cert)
}

func marshalDBCCert(cert *keydir.DBCCert) ([]byte, error) {
	var err error
	r := &dbccert{
		DBCSignature:    cert.DBCSignature,
		IssuerSignature: cert.IssuerSignature,
	}
	r.Subject, err = marshalDBCCertSubject(cert.Subject)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(*r)
}

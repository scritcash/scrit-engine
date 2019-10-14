package types

import (
	"crypto/elliptic"
	"errors"
)

var (
	// ErrSuiteUnknown is returned when a BlindSuite is unknown.
	ErrSuiteUnknown = errors.New("scrit/types: BlindSuite unknown")
	ErrFormat       = errors.New("scrit/types: Format or serialization incorrect")
	ErrFormatSize   = errors.New("scrit/types: Format or serialization incorrect, size mismatch")
	ErrKeyNotFound  = errors.New("scrit/types: Cannot find key with given keyID")
	ErrRandom       = errors.New("scrit/types: Cannot generate random value")
)

const (
	SuiteSecpk256 = byte(0x01)
	SuiteNist256  = byte(0x02)
)

// BlindSuite decribes a blinding suite.
type BlindSuite struct {
	CurveID    byte
	Curve      func() elliptic.Curve // Curve returns the curve.
	PointSize  int                   // Size of serialized Point
	SkalarSize int                   // Size of serialized Skalar
}

// // Secpk256 returns the Secpk256 BlindSuite.
// func Secpk256() BlindSuite {
// 	return BlindSuite{
// 		CurveID:    0x01,
// 		Curve:      func() elliptic.Curve { return btcec.S256() },
// 		PointSize:  33,
// 		SkalarSize: 32,
// 	}
// }

// Nist256 returns the Nist256 BlindSuite.
func Nist256() BlindSuite {
	return BlindSuite{
		CurveID:    0x02,
		Curve:      elliptic.P256,
		PointSize:  33,
		SkalarSize: 32,
	}
}

func New(curveID byte) (BlindSuite, error) {
	switch curveID {
	// case 0x01:
	// 	return Secpk256(), nil
	case 0x02:
		return Nist256(), nil
	}
	return BlindSuite{}, ErrSuiteUnknown
}

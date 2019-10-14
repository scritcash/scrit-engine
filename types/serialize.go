package types

import (
	"encoding/binary"
	"scrit/blind"
)

const (
	TPubKey              = byte(0x01) // s
	TSigServerParams     = byte(0x03)
	TBlindRequestPublic  = byte(0x04) // s
	TBlindRequestPrivate = byte(0x05) // s
	TBlindSignature      = byte(0x06) // s
	TSignature           = byte(0x07) // s
)

func prePad(d []byte, l int) []byte {
	if len(d) > l {
		panic("Prepadding excessive length input.")
	}
	if len(d) == l {
		return d
	}
	r := make([]byte, l)
	copy(r[l-len(d):], d)
	return r
}

func (self BlindSuite) MarshalPubKey(pubkey *blind.Point) []byte {
	r := make([]byte, 2, 2+self.PointSize)
	r[0] = TPubKey
	r[1] = self.CurveID
	r = append(r, prePad(pubkey.Marshal(), self.PointSize)...)
	return r
}

func UnmarshalPubKey(d []byte) (*blind.Point, BlindSuite, error) {
	if len(d) < 2 {
		return nil, BlindSuite{}, ErrFormatSize
	}
	if d[0] != TPubKey {
		return nil, BlindSuite{}, ErrFormat
	}
	bs, err := New(d[1])
	if err != nil {
		return nil, bs, err
	}
	if len(d) != 2+bs.PointSize {
		return nil, BlindSuite{}, ErrFormatSize
	}
	return blind.UnmarshalPoint(blind.NewCurve(bs.Curve()), d[2:]), bs, nil
}

func (self BlindSuite) MarshalBlindSignature(s *blind.Skalar, publicKey *blind.Point) []byte {
	r := make([]byte, 2, 2+self.SkalarSize+self.PointSize)
	r[0] = TBlindSignature
	r[1] = self.CurveID
	r = append(r, prePad(s.Marshal(), self.SkalarSize)...)
	r = append(r, prePad(publicKey.Marshal(), self.PointSize)...)
	return r
}

func UnmarshalBlindSignature(d []byte) (s *blind.Skalar, publicKey *blind.Point, suite BlindSuite, err error) {
	if len(d) < 2 {
		return nil, nil, BlindSuite{}, ErrFormatSize
	}
	if d[0] != TBlindSignature {
		return nil, nil, BlindSuite{}, ErrFormat
	}
	bs, err := New(d[1])
	if err != nil {
		return nil, nil, bs, err
	}
	if len(d) != 2+bs.SkalarSize+bs.PointSize {
		return nil, nil, BlindSuite{}, ErrFormatSize
	}
	s = blind.UnmarshalSkalar(d[2 : 2+bs.SkalarSize])
	publicKey = blind.UnmarshalPoint(blind.NewCurve(bs.Curve()), d[2+bs.SkalarSize:2+bs.SkalarSize+bs.PointSize])
	return s, publicKey, bs, nil
}

func (self BlindSuite) MarshalSignature(pubkey *blind.Point, s *blind.Skalar, r *blind.Point) []byte {
	ret := make([]byte, 2, 2+self.SkalarSize+(2*self.PointSize))
	ret[0] = TSignature
	ret[1] = self.CurveID
	ret = append(ret, prePad(pubkey.Marshal(), self.PointSize)...)
	ret = append(ret, prePad(r.Marshal(), self.PointSize)...)
	ret = append(ret, prePad(s.Marshal(), self.SkalarSize)...)
	return ret
}

func UnmarshalSignature(d []byte) (pubkey *blind.Point, s *blind.Skalar, r *blind.Point, suite BlindSuite, err error) {
	if len(d) < 2 {
		return nil, nil, nil, BlindSuite{}, ErrFormatSize
	}
	if d[0] != TSignature {
		return nil, nil, nil, BlindSuite{}, ErrFormat
	}
	suite, err = New(d[1])
	if err != nil {
		return nil, nil, nil, suite, err
	}
	if len(d) != 2+suite.SkalarSize+(2*suite.PointSize) {
		return nil, nil, nil, BlindSuite{}, ErrFormatSize
	}
	pubkey = blind.UnmarshalPoint(blind.NewCurve(suite.Curve()), d[2:2+suite.PointSize])
	r = blind.UnmarshalPoint(blind.NewCurve(suite.Curve()), d[2+suite.PointSize:2+suite.PointSize+suite.PointSize])
	s = blind.UnmarshalSkalar(d[2+suite.PointSize+suite.PointSize : 2+suite.PointSize+suite.PointSize+suite.SkalarSize])
	return
}

func (self BlindSuite) MarshalSignatureRequest(sr *blind.Skalar, m, n []byte, Q *blind.Point) (public, private []byte) {
	public = make([]byte, 2, 2+self.SkalarSize)
	public[0] = TBlindRequestPublic
	public[1] = self.CurveID
	public = append(public, prePad(sr.Marshal(), self.SkalarSize)...)
	private = make([]byte, 2+len(m)+len(n)+16+self.PointSize)
	private[0] = TBlindRequestPrivate
	private[1] = self.CurveID
	binary.BigEndian.PutUint64(private[2:10], uint64(len(m)))
	copy(private[10:], m)
	binary.BigEndian.PutUint64(private[10+len(m):18+len(m)], uint64(len(n)))
	copy(private[18+len(m):], n)
	copy(private[18+len(m)+len(n):], prePad(Q.Marshal(), self.PointSize))
	return
}

func UnmarshalSignatureRequestPublic(d []byte) (sr *blind.Skalar, suite BlindSuite, err error) {
	if len(d) < 2 {
		return nil, BlindSuite{}, ErrFormatSize
	}
	if d[0] != TBlindRequestPublic {
		return nil, BlindSuite{}, ErrFormat
	}
	suite, err = New(d[1])
	if err != nil {
		return nil, suite, err
	}
	if len(d) != 2+suite.SkalarSize {
		return nil, BlindSuite{}, ErrFormatSize
	}
	sr = blind.UnmarshalSkalar(d[2 : 2+suite.SkalarSize])
	return
}

func UnmarshalSignatureRequestPrivate(d []byte) (m, n []byte, Q *blind.Point, suite BlindSuite, err error) {
	if len(d) < 2 {
		return nil, nil, nil, BlindSuite{}, ErrFormatSize
	}
	if d[0] != TBlindRequestPrivate {
		return nil, nil, nil, BlindSuite{}, ErrFormat
	}
	suite, err = New(d[1])
	if err != nil {
		return nil, nil, nil, suite, err
	}
	if len(d) < 18 {
		return nil, nil, nil, BlindSuite{}, ErrFormatSize
	}
	lenM := int(binary.BigEndian.Uint64(d[2:10]))
	if len(d) < 18+lenM {
		return nil, nil, nil, BlindSuite{}, ErrFormatSize
	}
	m = make([]byte, lenM)
	copy(m, d[10:10+lenM])
	lenN := int(binary.BigEndian.Uint64(d[10+lenM : 18+lenM]))
	if len(d) < 18+lenM+lenN {
		return nil, nil, nil, BlindSuite{}, ErrFormatSize
	}
	n = make([]byte, lenN)
	copy(n, d[18+lenM:18+lenM+lenN])
	Q = blind.UnmarshalPoint(blind.NewCurve(suite.Curve()), d[18+lenM+lenN:18+lenM+lenN+suite.PointSize])
	return
}

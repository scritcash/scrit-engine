package types

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"scrit/blind"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	KeySize   = chacha20poly1305.KeySize
	NonceSize = chacha20poly1305.NonceSizeX
)

var Overhead = 0

func init() {
	x, err := chacha20poly1305.NewX(make([]byte, KeySize))
	if err != nil {
		panic(err)
	}
	Overhead = x.Overhead()
}

type KeyManager interface {
	Factory() (keyID uint64, key *[KeySize]byte)
	Lookup(keyID uint64) (key *[KeySize]byte)
}

func genNonce() *[NonceSize]byte {
	r := new([NonceSize]byte)
	_, err := io.ReadFull(rand.Reader, r[:])
	if err != nil {
		return nil
	}
	return r
}

func (self BlindSuite) MarshalServerParams(q *blind.Point, k *blind.Skalar, keyManager KeyManager) ([]byte, error) {
	keyID, key := keyManager.Factory()
	if key == nil {
		return nil, ErrKeyNotFound
	}
	nonce := genNonce()
	if nonce == nil {
		return nil, ErrRandom
	}
	r := make([]byte, 2+self.PointSize+8+NonceSize+self.SkalarSize+Overhead)
	r[0] = TSigServerParams
	r[1] = self.CurveID
	copy(r[2:2+self.PointSize], prePad(q.Marshal(), self.PointSize))
	binary.BigEndian.PutUint64(r[2+self.PointSize:2+self.PointSize+8], keyID)
	copy(r[2+self.PointSize+8:2+self.PointSize+8+NonceSize], nonce[:])
	encrypt, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, err
	}
	encrypted := make([]byte, 0)
	encrypted = encrypt.Seal(encrypted, nonce[:], prePad(k.Marshal(), self.SkalarSize), r[0:2+self.PointSize+8])
	copy(r[2+self.PointSize+8+NonceSize:2+self.PointSize+8+NonceSize+self.SkalarSize+Overhead], encrypted)
	return r, nil
}

func UnmarshalServerParams(d []byte) (blindParam *blind.Point, suite BlindSuite, err error) {
	if len(d) < 2 {
		return nil, BlindSuite{}, ErrFormatSize
	}
	if d[0] != TSigServerParams {
		return nil, BlindSuite{}, ErrFormat
	}
	suite, err = New(d[1])
	if err != nil {
		return nil, suite, err
	}
	if len(d) < 2+suite.PointSize+8+NonceSize+suite.SkalarSize+Overhead {
		return nil, suite, ErrFormatSize
	}
	blindParam = blind.UnmarshalPoint(blind.NewCurve(suite.Curve()), d[2:2+suite.PointSize])
	return
}

func UnmarshalMyServerParams(d []byte, keyManager KeyManager) (k *blind.Skalar, suite BlindSuite, err error) {
	_, suite, err = UnmarshalServerParams(d)
	if err != nil {
		return
	}
	key := keyManager.Lookup(binary.BigEndian.Uint64(d[2+suite.PointSize : 2+suite.PointSize+8]))
	if key == nil {
		err = ErrKeyNotFound
		return
	}
	nonce := d[2+suite.PointSize+8 : 2+suite.PointSize+8+NonceSize]
	decrypt, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return
	}
	decrypted, err := decrypt.Open(make([]byte, 0), nonce, d[2+suite.PointSize+8+NonceSize:2+suite.PointSize+8+NonceSize+suite.SkalarSize+Overhead], d[0:2+suite.PointSize+8])
	if err != nil {
		return
	}
	k = blind.UnmarshalSkalar(decrypted)
	return
}

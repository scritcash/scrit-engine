package types

import (
	"encoding/binary"
	"errors"
)

var (
	ErrEncodingLength = errors.New("scrit/types: Format error, short")
)

// LengthEncode encodes data into a length encoded slice.
func LengthEncode(version uint16, entryType uint16, data []byte) []byte {
	r := make([]byte, 12+len(data))
	binary.BigEndian.PutUint16(r[0:2], version)
	binary.BigEndian.PutUint16(r[2:4], entryType)
	binary.BigEndian.PutUint64(r[4:12], uint64(len(data)))
	copy(r[12:], data)
	return r
}

// LengthDecode decodes data that has been length encoded.
func LengthDecode(d []byte) (version, entryType uint16, data []byte, err error) {
	if len(d) < 12 {
		return 0, 0, nil, ErrEncodingLength
	}
	version = binary.BigEndian.Uint16(d[0:2])
	entryType = binary.BigEndian.Uint16(d[2:4])
	length := binary.BigEndian.Uint64(d[4:12])
	if uint64(len(d)) < 12+length {
		return 0, 0, nil, ErrEncodingLength
	}
	data = make([]byte, length)
	copy(data, d[12:12+length])
	return
}

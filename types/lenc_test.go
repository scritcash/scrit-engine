package types

import (
	"bytes"
	"testing"
)

func TestLengthEncoding(t *testing.T) {
	tData := []byte("Some data")
	enc := LengthEncode(1, 2, tData)
	version, entrytype, dec, err := LengthDecode(enc)
	if err != nil {
		t.Fatalf("LengthDecode: %s", err)
	}
	if version != 1 {
		t.Error("Version mismatch")
	}
	if entrytype != 2 {
		t.Error("entryType mismatch")
	}
	if !bytes.Equal(tData, dec) {
		t.Error("data corrupt")
	}
}

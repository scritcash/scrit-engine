package token

import (
	"testing"
)

func TestBinaryTransactionMarshal(t *testing.T) {
	bt := &BinaryTransaction{
		InputTokens: [][]byte{[]byte("data1")},
		Outputs: []BinaryOutput{BinaryOutput{
			Value: 3,
			BlindSignatureRequest:   []byte("data4"),
			ServerBlindingParameter: []byte("data5"),
		}},
		TokenSignatures: [][]byte{[]byte("data2")},
		OwnerSignatures: [][]byte{[]byte("data3")},
	}
	d, err := bt.Marshal()
	if err != nil {
		t.Fatalf("Marshal %s", err)
	}
	bt2, err := new(BinaryTransaction).Unmarshal(d)
	if err != nil {
		t.Fatalf("Unmarshal %s", err)
	}
	_ = bt2
}

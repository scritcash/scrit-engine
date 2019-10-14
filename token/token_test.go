package token

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"scrit/blind"
	"scrit/types"
	"testing"
)

func TestTokenWithSignature(t *testing.T) {
	suite, err := types.New(types.SuiteNist256)
	if err != nil {
		t.Fatalf("New Suite: %s", err)
	}
	signer, err := blind.NewSigner(suite.Curve(), rand.Reader)
	if err != nil {
		t.Fatalf("NewSigner: %s", err)
	}
	publicKey := signer.Public()
	s := (*blind.Skalar)(big.NewInt(39812))

	td := &TokenWithSignatures{
		Token: &Token{
			Type:        TSplitOwner,
			FirstOwner:  []byte("first owner"),
			SecondOwner: []byte("second owner"),
			CutOffTime:  10291,
		},
		Signatures: []TokenSignature{TokenSignature{
			BlindSuite: suite.CurveID,
			PubKey:     publicKey,
			S:          s,
			R:          publicKey,
		}},
	}
	tdM, err := td.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %s", err)
	}
	td2, err := new(TokenWithSignatures).Unmarshal(tdM)
	if err != nil {
		t.Fatalf("Unmarshal: %s", err)
	}
	if td.Signatures[0].BlindSuite != td2.Signatures[0].BlindSuite {
		t.Error("BlindSuite")
	}
	if !bytes.Equal(td.Signatures[0].S.Marshal(), td2.Signatures[0].S.Marshal()) {
		t.Error("S")
	}
	if !bytes.Equal(td.Signatures[0].R.Marshal(), td2.Signatures[0].R.Marshal()) {
		t.Error("R")
	}
	if !bytes.Equal(td.Signatures[0].PubKey.Marshal(), td2.Signatures[0].PubKey.Marshal()) {
		t.Error("PubKey")
	}
	if td.Token.Type != td2.Token.Type {
		t.Error("Type")
	}
	if td.Token.CutOffTime != td2.Token.CutOffTime {
		t.Error("CutOffTime")
	}
	if !bytes.Equal(td.Token.FirstOwner, td2.Token.FirstOwner) {
		t.Error("FirstOwner")
	}
	if !bytes.Equal(td.Token.SecondOwner, td2.Token.SecondOwner) {
		t.Error("SecondOwner")
	}
	if !bytes.Equal(td.Token.Random, td2.Token.Random) {
		t.Error("Random")
	}
}

func TestToken(t *testing.T) {
	tt := &Token{
		// Type: TNoOwner,
		// Type: TSingleOwner,
		Type:        TSplitOwner,
		FirstOwner:  []byte("first owner"),
		SecondOwner: []byte("second owner"),
		CutOffTime:  10291,
	}
	ttm, err := tt.Marshal()
	if err != nil {
		t.Errorf("Marshal: %s", err)
	}
	// spew.Dump(ttm)
	tt2, err := new(Token).Unmarshal(ttm)
	if err != nil {
		t.Errorf("Unmarshal: %s", err)
	}
	if tt2 == nil {
		t.Fatal("Decode nil")
	}
	if tt.FirstOwner != nil {
		if tt2.FirstOwner == nil || !bytes.Equal(tt.FirstOwner, tt2.FirstOwner) {
			t.Error("FirstOwner")
		}
	}
	if tt.SecondOwner != nil {
		if tt2.SecondOwner == nil || !bytes.Equal(tt.SecondOwner, tt2.SecondOwner) {
			t.Error("SecondOwner")
		}
	}
	if tt.CutOffTime != tt2.CutOffTime {
		t.Error("CutOffTime")
	}
	if tt.Type != tt2.Type {
		t.Error("Type")
	}
}

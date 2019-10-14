package blind

import (
	"crypto/rand"
	"testing"

	"github.com/btcsuite/btcd/btcec"
)

func TestClearSign(t *testing.T) {
	msg := []byte("Message to be signed")
	signer, err := NewSigner(btcec.S256(), rand.Reader)
	if err != nil {
		t.Fatalf("NewSigner: %s", err)
	}
	publicKey := signer.Public()
	sig, err := signer.ECDSASign(msg)
	if err != nil {
		t.Fatalf("ECDSASign: %s", err)
	}
	if ok := publicKey.ECDSAVerify(msg, sig); !ok {
		t.Error("Signature did not verify")
	}
	if ok := publicKey.ECDSAVerify([]byte("bad message"), sig); ok {
		t.Error("Signature verified corrupt message")
	}
}

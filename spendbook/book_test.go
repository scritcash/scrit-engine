package spendbook

import (
	"bytes"
	"testing"
	"time"
)

func TestBook(t *testing.T) {
	book, err := New("/tmp/spendbooktest")
	if err != nil {
		t.Fatalf("New: %s", err)
	}
	defer book.Close()
	book.RunGCService(time.Second * 1)

	if _, spent := book.isSpent([]byte("testkey")); spent {
		t.Error("Value falsly recorded as spent")
	}

	_, err = book.spendIfUnknown([]byte("testkey"), []byte("testvalue"), time.Second*2)
	if err != nil {
		t.Errorf("spendIfUnknown returned unexpected error: %s", err)
	}

	stored, spent := book.isSpent([]byte("testkey"))
	if !spent {
		t.Error("Value not recorded as spent")
	}

	if !bytes.Equal(stored, []byte("testvalue")) {
		t.Error("Wrong value returned by isSpent")
	}

	stored, err = book.spendIfUnknown([]byte("testkey"), []byte("testvalue"), time.Second*2)
	if err == nil {
		t.Error("spendIfUnkown should return error on spent token")
	}

	if !bytes.Equal(stored, []byte("testvalue")) {
		t.Error("Wrong value returned by spendIfUnknown")
	}

	_, err = book.spendIfUnknown([]byte("testkey2"), []byte("testvalue2"), time.Second*2)
	if err != nil {
		t.Errorf("spendIfUnknown returned unexpected error: %s", err)
	}

}

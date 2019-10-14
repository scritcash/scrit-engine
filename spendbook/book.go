// Package spendbook implements spendbook functionality
package spendbook

/*
ToDo: Is Spent?
*/

import (
	"errors"
	"time"

	"github.com/dgraph-io/badger"
)

const (
	gcFactor = 0.7
)

const (
	TypeToken = 't'
	TypeParam = 'p'
)

var (
	timeNow     = func() uint64 { return uint64(time.Now().Unix()) }
	timeNowTime = func() time.Time { return time.Now() }
	ErrorSpent  = errors.New("spendbook: Value already spent")
	// SkewSafety is the duration beyond expiry for which an entry should be stored
	SkewSafety = time.Hour * 24 * 30
)

// Book implements a simple spendbook.
type Book struct {
	db     *badger.DB
	stopGC chan interface{}
}

// New returns a new spendbook.
func New(dir string) (*Book, error) {
	opts := badger.DefaultOptions
	opts.Dir = dir
	opts.ValueDir = dir
	db, err := badger.Open(opts)
	if err != nil {
		return nil, err
	}
	return &Book{
		db:     db,
		stopGC: make(chan interface{}, 1),
	}, nil
}

// Close a spendbook.
func (self *Book) Close() {
	self.stopGC <- struct{}{}
	self.db.Close()
}

// GCRun runs the garbage collection.
func (self *Book) GCRun() error {
	return self.db.RunValueLogGC(gcFactor)
}

// RunGCService runs the garbage collection serivce every duration.
func (self *Book) RunGCService(dur time.Duration) {
	go func() {
		ticker := time.NewTicker(dur)
		for {
			select {
			case <-ticker.C:
				self.GCRun()
			case <-self.stopGC:
				ticker.Stop()
			}
		}
	}()
}

func (self *Book) spendIfUnknown(key, value []byte, ttl time.Duration) (storedValue []byte, err error) {
	err = self.db.Update(func(txn *badger.Txn) error {
		current, err := txn.Get(key)
		if err != badger.ErrKeyNotFound {
			storedValue, _ = current.ValueCopy(nil)
			return ErrorSpent
		}
		return txn.SetWithTTL(key, value, ttl)
	})
	return
}

func (self *Book) isSpent(key []byte) (storedValue []byte, spent bool) {
	err := self.db.View(func(txn *badger.Txn) error {
		current, err := txn.Get(key)
		if err == nil {
			storedValue, _ = current.ValueCopy(nil)
		}
		return err
	})
	if err == badger.ErrKeyNotFound {
		return nil, false
	}
	return storedValue, true
}

// Package appstorebudget admits bounded cooperating operations within a process.
package appstorebudget

import (
	"errors"
	"sync"
)

var ErrInvalid = errors.New("application-store operation requires a nonzero store ID")
var ErrBusy = errors.New("application-store operation admission busy")

var mu sync.Mutex
var slots [2][16]byte

// TryAcquire admits at most two operations and at most one for a given store.
func TryAcquire(store [16]byte) (func(), error) {
	if store == ([16]byte{}) {
		return nil, ErrInvalid
	}
	mu.Lock()
	free := -1
	for i := range slots {
		if slots[i] == store {
			mu.Unlock()
			return nil, ErrBusy
		}
		if slots[i] == ([16]byte{}) && free < 0 {
			free = i
		}
	}
	if free < 0 {
		mu.Unlock()
		return nil, ErrBusy
	}
	slots[free] = store
	mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			mu.Lock()
			slots[free] = [16]byte{}
			mu.Unlock()
		})
	}, nil
}

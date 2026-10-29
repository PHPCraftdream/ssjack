// Package kdfgate serializes cooperating KDF batches within one process.
package kdfgate

import (
	"context"
	"errors"
	"sync"
)

var ErrInvalidContext = errors.New("KDF admission requires a valid context")
var slot = make(chan struct{}, 1)

// Acquire waits for admission; cancellation never revokes an already returned lease.
func Acquire(ctx context.Context) (func(), error) {
	if ctx == nil {
		return nil, ErrInvalidContext
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case slot <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-slot
			return nil, err
		}
		return releaseOnce(), nil
	case <-ctx.Done():
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, ErrInvalidContext
	}
}

// TryAcquire never waits. A held batch must finish before its lease is released.
func TryAcquire() (func(), bool) {
	select {
	case slot <- struct{}{}:
		return releaseOnce(), true
	default:
		return nil, false
	}
}

func releaseOnce() func() {
	var once sync.Once
	return func() { once.Do(func() { <-slot }) }
}

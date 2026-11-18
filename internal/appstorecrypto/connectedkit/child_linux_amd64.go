//go:build linux && amd64

// Package connectedkit holds child-process and SSH-target helpers for connected acceptance tests.
package connectedkit

import (
	"crypto/sha256"
	"encoding/base64"
	"sync"
)

const (
	// ConnectedGate enables connected CI acceptance tests.
	ConnectedGate = "SSJACK_TEXT_ADAPTER_CI_ACCEPTANCE"
	// ConnectedSecret is the synthetic secret shared by connected scenarios.
	ConnectedSecret = "synthetic-connected-secret"
	maxChildLog     = 16 << 10
)

// BoundedChildLog collects child diagnostics up to 16 KiB.
type BoundedChildLog struct {
	mu        sync.Mutex
	data      []byte
	truncated bool
}

func (l *BoundedChildLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	remaining := maxChildLog - len(l.data)
	if remaining > 0 {
		if len(p) > remaining {
			l.data = append(l.data, p[:remaining]...)
		} else {
			l.data = append(l.data, p...)
		}
	}
	if len(p) > remaining {
		l.truncated = true
	}
	return len(p), nil
}

func (l *BoundedChildLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	result := string(l.data)
	if l.truncated {
		result += "\n[child diagnostics truncated at 16 KiB]"
	}
	return result
}

// ConnectedVariantID derives a distinct grant ID for a labelled variant.
func ConnectedVariantID(base, label string) string {
	digest := sha256.Sum256([]byte(base + label))
	return base64.RawURLEncoding.EncodeToString(digest[:16])
}

const (
	// PairLongSecret and PairShortSecret are synthetic credentials that must never be logged.
	PairLongSecret  = "pair-synthetic-key-long-v1"
	PairShortSecret = "pair-synthetic-key"
)

// Truncated reports whether output beyond the limit was dropped.
func (l *BoundedChildLog) Truncated() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.truncated
}

// Bytes returns a copy of the collected output.
func (l *BoundedChildLog) Bytes() []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]byte(nil), l.data...)
}

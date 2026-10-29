package recoverybinding_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/recovery"
	"github.com/PHPCraftdream/ssjack/internal/recoverybinding"
)

func input() recovery.Binding {
	b := recovery.Binding{
		Stage: recovery.Reservation, Invocation: "inv", Resource: "res",
		Expected: recovery.State{Resource: "res", Generation: 7, Transaction: "old"},
		Next:     recovery.State{Resource: "res", Generation: 8},
	}
	for i := range b.RequestHash {
		b.Expected.Hash[i], b.Next.Hash[i], b.RequestHash[i] = 0x11, 0x22, 0x33
	}
	return b
}

func unsigned(b recovery.Binding) recovery.Binding {
	b.Transaction, b.Next.Transaction = "", ""
	return b
}

func committed(t *testing.T) recovery.Binding {
	t.Helper()
	b, err := recoverybinding.New(input())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestIndependentWireVector(t *testing.T) {
	before := input()
	b, err := recoverybinding.New(before)
	if err != nil || recoverybinding.Validate(b) != nil {
		t.Fatalf("valid commitment: %v", err)
	}
	literal := "ssjack-recovery-binding-v1\x00\x02\x00\x03inv\x00\x03res\x00\x03res" +
		"\x00\x00\x00\x00\x00\x00\x00\x07" + strings.Repeat("\x11", 32) +
		"\x00\x03old\x00\x03res\x00\x00\x00\x00\x00\x00\x00\x08" +
		strings.Repeat("\x22", 32) + strings.Repeat("\x33", 32)
	sum := sha256.Sum256([]byte(literal))
	if b.Transaction != hex.EncodeToString(sum[:]) || b.Next.Transaction != b.Transaction {
		t.Fatal("independent binary commitment mismatch")
	}
	for _, wrong := range []string{
		strings.Replace(literal, "ssjack-recovery-binding-v1", "ssjack-recovery-binding-v2", 1),
		strings.Replace(literal, "v1\x00\x02", "v1\x02", 1),
		strings.Replace(literal, "\x00\x03inv", "\x03\x00inv", 1),
	} {
		h := sha256.Sum256([]byte(wrong))
		if b.Transaction == hex.EncodeToString(h[:]) {
			t.Fatal("wrong domain, separator or byte order matched")
		}
	}
	if unsigned(b) != before || input() != before {
		t.Fatal("semantic input changed")
	}
	again, err := recoverybinding.New(before)
	if err != nil || again != b {
		t.Fatal("commitment is not deterministic")
	}
}

func TestSemanticMutationsRequireDifferentTransactions(t *testing.T) {
	cases := map[string]func(*recovery.Binding){
		"stage":      func(b *recovery.Binding) { b.Stage = recovery.Initialization },
		"invocation": func(b *recovery.Binding) { b.Invocation = "other" },
		"resource": func(b *recovery.Binding) {
			b.Resource, b.Expected.Resource, b.Next.Resource = "other", "other", "other"
		},
		"generations":       func(b *recovery.Binding) { b.Expected.Generation, b.Next.Generation = 9, 10 },
		"expected-hash":     func(b *recovery.Binding) { b.Expected.Hash[0] = 0x44 },
		"next-hash":         func(b *recovery.Binding) { b.Next.Hash[0] = 0x55 },
		"prior-transaction": func(b *recovery.Binding) { b.Expected.Transaction = "older" },
		"request-hash":      func(b *recovery.Binding) { b.RequestHash[0] = 0x66 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			b := committed(t)
			mutate(&b)
			if !recovery.ValidBinding(b) {
				t.Fatal("mutation was masked by structural rejection")
			}
			if !errors.Is(recoverybinding.Validate(b), recoverybinding.ErrInvalid) {
				t.Fatal("tampered commitment admitted")
			}
			rebound, err := recoverybinding.New(unsigned(b))
			if err != nil || rebound.Transaction == b.Transaction || recoverybinding.Validate(rebound) != nil {
				t.Fatalf("changed valid binding did not get a new valid ID: %v", err)
			}
		})
	}
}

func TestStructuralAndEncodingRejections(t *testing.T) {
	cases := map[string]func(*recovery.Binding){
		"stage":                      func(b *recovery.Binding) { b.Stage = 0 },
		"empty-invocation":           func(b *recovery.Binding) { b.Invocation = "" },
		"long-invocation":            func(b *recovery.Binding) { b.Invocation = strings.Repeat("i", 129) },
		"space":                      func(b *recovery.Binding) { b.Invocation = "bad id" },
		"control":                    func(b *recovery.Binding) { b.Invocation = "bad\x00id" },
		"unicode":                    func(b *recovery.Binding) { b.Invocation = "é" },
		"long-resource":              func(b *recovery.Binding) { b.Resource = strings.Repeat("r", 129) },
		"expected-resource":          func(b *recovery.Binding) { b.Expected.Resource = "other" },
		"long-expected-resource":     func(b *recovery.Binding) { b.Expected.Resource = strings.Repeat("r", 129) },
		"next-resource":              func(b *recovery.Binding) { b.Next.Resource = "other" },
		"long-next-resource":         func(b *recovery.Binding) { b.Next.Resource = strings.Repeat("r", 129) },
		"generation-gap":             func(b *recovery.Binding) { b.Next.Generation++ },
		"overflow":                   func(b *recovery.Binding) { b.Expected.Generation, b.Next.Generation = ^uint64(0), 0 },
		"same-hashes":                func(b *recovery.Binding) { b.Next.Hash = b.Expected.Hash },
		"missing-old-transaction":    func(b *recovery.Binding) { b.Expected.Transaction = "" },
		"long-old-transaction":       func(b *recovery.Binding) { b.Expected.Transaction = strings.Repeat("t", 129) },
		"invalid-old-transaction":    func(b *recovery.Binding) { b.Expected.Transaction = "bad\x7f" },
		"prefilled-transaction":      func(b *recovery.Binding) { b.Transaction = "caller-id" },
		"prefilled-next-transaction": func(b *recovery.Binding) { b.Next.Transaction = "caller-id" },
		"genesis-with-transaction":   func(b *recovery.Binding) { b.Expected.Generation, b.Next.Generation = 0, 1 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			b := input()
			mutate(&b)
			got, err := recoverybinding.New(b)
			if !errors.Is(err, recoverybinding.ErrInvalid) || got != (recovery.Binding{}) {
				t.Fatalf("invalid input exposed a binding: %v", err)
			}
		})
	}
	for _, mutate := range []func(*recovery.Binding){
		func(b *recovery.Binding) { b.Transaction, b.Next.Transaction = "legacy-id", "legacy-id" },
		func(b *recovery.Binding) {
			b.Transaction = strings.ToUpper(b.Transaction)
			b.Next.Transaction = b.Transaction
		},
		func(b *recovery.Binding) { b.Next.Transaction = "different" },
	} {
		b := committed(t)
		mutate(&b)
		if !errors.Is(recoverybinding.Validate(b), recoverybinding.ErrInvalid) {
			t.Fatal("noncanonical or inconsistent transaction admitted")
		}
	}
	if recoverybinding.Validate(recovery.Binding{}) == nil {
		t.Fatal("zero binding admitted")
	}
}

func TestValidBounds(t *testing.T) {
	for _, generation := range []uint64{0, 7, 9007199254740992, ^uint64(0) - 1} {
		b := input()
		b.Expected.Generation, b.Next.Generation = generation, generation+1
		if generation == 0 {
			b.Expected.Transaction = ""
		}
		b.Invocation = strings.Repeat("i", 128)
		b.Resource = strings.Repeat("r", 128)
		b.Expected.Resource, b.Next.Resource = b.Resource, b.Resource
		got, err := recoverybinding.New(b)
		if err != nil || recoverybinding.Validate(got) != nil {
			t.Fatalf("valid bounded generation %d: %v", generation, err)
		}
	}
}

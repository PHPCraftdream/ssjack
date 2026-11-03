//go:build linux

package appstoresink

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
)

func fixedFixture(t *testing.T) (string, Binding) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fixed-consumer")
	source := filepath.Join(t.TempDir(), "consumer.go")
	if err := os.WriteFile(source, []byte(fixedConsumerSource), 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("go", "build", "-o", path, source)
	command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=local")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build synthetic native fixture: %v\n%s", err, output)
	}
	program, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	reference, err := appstoreref.New([16]byte{1}, [16]byte{2}, [16]byte{3}, [16]byte{4})
	if err != nil {
		t.Fatal(err)
	}
	return path, Binding{Reference: reference, EncodedHash: [32]byte{1}, ArtifactHash: sha256.Sum256(program), Target: [32]byte{3}, Revision: [32]byte{4}, Purpose: [32]byte{5}, ExpiresAt: time.Now().Add(time.Hour)}
}
func fixtureConsumer(t *testing.T, path string, binding Binding) *Consumer {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(Config{Program: f, Binding: binding})
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}
func sinkContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}
func TestFixedNativeConsumer(t *testing.T) {
	path, binding := fixedFixture(t)
	t.Run("exact-code-pipe-and-one-use", func(t *testing.T) {
		c := fixtureConsumer(t, path, binding)
		ctx := sinkContext(t)
		wrong := binding.EncodedHash
		wrong[0] ^= 1
		if _, err := c.Begin(ctx, binding.Reference, wrong, 1); !errors.Is(err, ErrDenied) {
			t.Fatalf("wrong hash: %v", err)
		}
		const length = 90017
		delivery, err := c.Begin(ctx, binding.Reference, binding.EncodedHash, length)
		if err != nil {
			t.Fatal(err)
		}
		defer delivery.Close()
		buffer := make([]byte, maxChunk)
		defer clear(buffer)
		for offset := 0; offset < length; {
			n := len(buffer)
			if n > length-offset {
				n = length - offset
			}
			for i := range buffer[:n] {
				buffer[i] = byte((offset + i) % 251)
			}
			if sent, err := delivery.Write(buffer[:n]); err != nil || sent != n {
				t.Fatalf("fixed write: %v", err)
			}
			offset += n
		}
		result, err := delivery.Finish()
		if err != nil || !result.Complete || !result.MayHaveDelivered || result.Bytes != length {
			t.Fatalf("fixed receipt: %+v %v", result, err)
		}
		if _, err := c.Begin(ctx, binding.Reference, binding.EncodedHash, 1); !errors.Is(err, ErrDenied) {
			t.Fatalf("reused grant: %v", err)
		}
	})
	t.Run("actual-consumer-scope", func(t *testing.T) {
		wrong := binding
		wrong.Target[0] ^= 1
		c := fixtureConsumer(t, path, wrong)
		if delivery, err := c.Begin(sinkContext(t), wrong.Reference, wrong.EncodedHash, 1); delivery != nil || !errors.Is(err, ErrDenied) {
			t.Fatalf("scope mismatch: %v", err)
		}
	})
	t.Run("expired-monotonic-cutoff", func(t *testing.T) {
		c := fixtureConsumer(t, path, binding)
		c.state.expires = time.Now().Add(-time.Second)
		if delivery, err := c.Begin(sinkContext(t), binding.Reference, binding.EncodedHash, 1); delivery != nil || !errors.Is(err, ErrDenied) {
			t.Fatalf("expired cutoff: %v", err)
		}
		if c.state.active.Load() != nil {
			t.Fatal("expired grant started a process")
		}
	})
	t.Run("concurrent-finish-is-unknown", func(t *testing.T) {
		delivery := &Delivery{state: &deliveryState{}}
		delivery.state.mu.Lock()
		defer delivery.state.mu.Unlock()
		result, err := delivery.Finish()
		if !errors.Is(err, ErrBusy) || !result.MayHaveDelivered || result.Complete {
			t.Fatalf("concurrent finish: %+v %v", result, err)
		}
	})
	t.Run("wrong-artifact-before-process", func(t *testing.T) {
		wrong := binding
		wrong.ArtifactHash[0] ^= 1
		c := fixtureConsumer(t, path, wrong)
		if delivery, err := c.Begin(sinkContext(t), wrong.Reference, wrong.EncodedHash, 1); delivery != nil || !errors.Is(err, ErrDenied) {
			t.Fatalf("artifact mismatch: %v", err)
		}
		if c.state.active.Load() != nil {
			t.Fatal("mismatched artifact started")
		}
	})
	t.Run("revoke-after-handoff", func(t *testing.T) {
		c := fixtureConsumer(t, path, binding)
		delivery, err := c.Begin(sinkContext(t), binding.Reference, binding.EncodedHash, 2)
		if err != nil {
			t.Fatal(err)
		}
		defer delivery.Close()
		if n, err := delivery.Write([]byte{0}); n != 1 || err != nil {
			t.Fatalf("first byte: %v", err)
		}
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
		result, err := delivery.Finish()
		if err == nil || result.Complete || !result.MayHaveDelivered || result.Bytes != 1 {
			t.Fatalf("revoked handoff: %+v %v", result, err)
		}
	})
	t.Run("cancellation-before-secret", func(t *testing.T) {
		c := fixtureConsumer(t, path, binding)
		ctx, cancel := context.WithCancel(sinkContext(t))
		delivery, err := c.Begin(ctx, binding.Reference, binding.EncodedHash, 1)
		if err != nil {
			t.Fatal(err)
		}
		defer delivery.Close()
		cancel()
		if n, err := delivery.Write([]byte{0}); n != 0 || err == nil {
			t.Fatal("cancelled handoff succeeded")
		}
		result, err := delivery.Finish()
		if err == nil || result.Complete || result.MayHaveDelivered || result.Bytes != 0 {
			t.Fatalf("cancelled result: %+v %v", result, err)
		}
	})
	t.Run("consumer-refusal-is-unknown", func(t *testing.T) {
		c := fixtureConsumer(t, path, binding)
		delivery, err := c.Begin(sinkContext(t), binding.Reference, binding.EncodedHash, 1)
		if err != nil {
			t.Fatal(err)
		}
		defer delivery.Close()
		_, _ = delivery.Write([]byte{17})
		result, err := delivery.Finish()
		if err == nil || result.Complete || !result.MayHaveDelivered {
			t.Fatalf("consumer refusal: %+v %v", result, err)
		}
	})
}

func TestFixedConsumerRejectsScriptAndExpiredBinding(t *testing.T) {
	path, binding := fixedFixture(t)
	expired := binding
	expired.ExpiresAt = time.Now().Add(-time.Second)
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if c, err := New(Config{Program: f, Binding: expired}); c != nil || !errors.Is(err, ErrInvalid) {
		t.Fatalf("expired binding: %v", err)
	}
	program := make([]byte, 128)
	copy(program, "#!/bin/sh\nexit 0\n")
	script := filepath.Join(t.TempDir(), "not-native")
	if err := os.WriteFile(script, program, 0700); err != nil {
		t.Fatal(err)
	}
	binding.ArtifactHash = sha256.Sum256(program)
	c := fixtureConsumer(t, script, binding)
	if delivery, err := c.Begin(sinkContext(t), binding.Reference, binding.EncodedHash, 0); delivery != nil || !errors.Is(err, ErrUnsupported) {
		t.Fatalf("script accepted: %v", err)
	}
	if c.state.active.Load() != nil {
		t.Fatal("script execution attempted")
	}
}

package appstorecrypto

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstoreheader"
)

func TestRecordAdmissionClosedBusyAndScope(t *testing.T) {
	h := header(t)
	m, err := derive(context.Background(), h, []byte("synthetic record-admission fixture"), fake)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	plain := finalRecord(h)
	for _, row := range []struct {
		ctx   context.Context
		h     appstoreheader.Header
		index uint32
		final bool
		data  []byte
	}{
		{nil, h, ^uint32(0), true, plain},
		{context.Background(), appstoreheader.Header{}, ^uint32(0), true, plain},
		{context.Background(), h, 0, true, plain},
		{context.Background(), h, ^uint32(0), false, plain},
		{context.Background(), h, 1, false, plain},
		{context.Background(), h, ^uint32(0), true, plain[:47]},
		{context.Background(), h, ^uint32(0), true, append(append([]byte(nil), plain...), 0)},
	} {
		out, err := m.sealRecord(row.ctx, row.h, row.index, row.final, row.data)
		if !errors.Is(err, ErrRecord) || out != nil {
			t.Fatalf("invalid record context admitted: %v", err)
		}
	}
	for _, size := range []int{16047, 16049} {
		out, err := m.openRecord(context.Background(), h, ^uint32(0), true, make([]byte, size))
		if !errors.Is(err, ErrRecord) || out != nil {
			t.Fatal("wrong ciphertext size admitted")
		}
	}
	for _, offset := range []int{12, 80} {
		raw := h.Bytes()
		raw[offset] ^= 0x80
		other, err := appstoreheader.Parse(raw[:])
		if err != nil {
			t.Fatal(err)
		}
		out, err := m.sealRecord(context.Background(), other, ^uint32(0), true, plain)
		if !errors.Is(err, ErrRecord) || out != nil {
			t.Fatal("foreign master context admitted")
		}
	}
	m.state.mu.Lock()
	out, err := m.sealRecord(context.Background(), h, ^uint32(0), true, plain)
	m.state.mu.Unlock()
	if !errors.Is(err, ErrBusy) || out != nil {
		t.Fatal("busy master admitted another record")
	}
	m.Close()
	for _, closed := range []*Master{nil, {}, m} {
		out, err := closed.sealRecord(context.Background(), h, ^uint32(0), true, plain)
		if !errors.Is(err, ErrClosed) || out != nil {
			t.Fatal("closed/zero master encrypted")
		}
	}
}

func TestRecordCancellationAndFinalFields(t *testing.T) {
	h := header(t)
	m, err := derive(context.Background(), h, []byte("synthetic cancelled-record fixture"), fake)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	plain := finalRecord(h)
	for _, offset := range []int{0, 4, 12} {
		bad := append([]byte(nil), plain...)
		bad[offset] ^= 1
		out, err := m.sealRecord(context.Background(), h, ^uint32(0), true, bad)
		if !errors.Is(err, ErrRecord) || out != nil {
			t.Fatal("invalid final fields encrypted")
		}
	}
	ciphertext := oracleSeal(t, m.state.key, h, ^uint32(0), true, 48, 0, plain)
	for _, sealing := range []bool{true, false} {
		input := plain
		if !sealing {
			input = ciphertext
		}
		before := append([]byte(nil), input...)
		ctx, cancel := context.WithCancel(context.Background())
		calls := 0
		out, err := m.transformRecord(ctx, h, ^uint32(0), true, input, sealing, func(uint32) {
			calls++
			if m.state.mu.TryLock() {
				m.state.mu.Unlock()
				t.Error("record did not protect owned key")
			}
			cancel()
		})
		cancel()
		if !errors.Is(err, context.Canceled) || out != nil || calls != 1 || !bytes.Equal(input, before) {
			t.Fatal("cancellation published partial bytes or changed caller input")
		}
		ctx, cancel = context.WithCancel(context.Background())
		cancel()
		out, err = m.transformRecord(ctx, h, ^uint32(0), true, input, sealing, nil)
		if !errors.Is(err, context.Canceled) || out != nil {
			t.Fatal("already cancelled record started")
		}
	}
	for _, position := range []int{0, len(ciphertext) - 1} {
		bad := append([]byte(nil), ciphertext...)
		bad[position] ^= 1
		out, err := m.openRecord(context.Background(), h, ^uint32(0), true, bad)
		if !errors.Is(err, ErrAuthentication) || out != nil {
			t.Fatal("outer ciphertext tampering admitted")
		}
	}
	clear(ciphertext)
}

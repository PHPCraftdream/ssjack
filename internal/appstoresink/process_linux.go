//go:build linux

package appstoresink

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"io"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
)

type deliveryState struct {
	mu            sync.Mutex
	owner         *consumerState
	ctx           context.Context
	cancel        context.CancelFunc
	command       *exec.Cmd
	input, output *os.File
	identity      [2]uint64
	frame         [64]byte
	length, sent  uint64
	possible      bool
	hash          hash.Hash
	closed        atomic.Bool
	wait          sync.Once
	waitErr       error
}

func beginDelivery(c *Consumer, ctx context.Context, ref appstoreref.Ref, encoded [32]byte, length uint64) (*Delivery, error) {
	if ctx == nil || length > 1<<40 {
		return nil, ErrInvalid
	}
	deadline, ok := ctx.Deadline()
	if !ok || deadline.After(time.Now().Add(time.Hour)) {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := checkConsumer(c, ref, encoded); err != nil {
		return nil, err
	}
	s := c.state
	if !s.mu.TryLock() {
		return nil, ErrBusy
	}
	if s.consumed || s.revoked.Load() || s.program == nil {
		s.mu.Unlock()
		return nil, ErrDenied
	}
	s.consumed = true
	operation, cancel := context.WithDeadline(ctx, s.expires)
	s.cancel.Store(&cancelSlot{cancel: cancel})
	frozen, identity, err := freezeProgram(operation, s.program, s.binding.ArtifactHash)
	if err != nil {
		cancel()
		s.mu.Unlock()
		return nil, err
	}
	defer frozen.Close()
	inputRead, inputWrite, err := os.Pipe()
	if err != nil {
		cancel()
		s.mu.Unlock()
		return nil, ErrUnavailable
	}
	outputRead, outputWrite, err := os.Pipe()
	if err != nil {
		_ = inputRead.Close()
		_ = inputWrite.Close()
		cancel()
		s.mu.Unlock()
		return nil, ErrUnavailable
	}
	command := exec.CommandContext(operation, "/proc/self/fd/3")
	command.Env = []string{}
	command.Dir = "/"
	command.ExtraFiles = []*os.File{frozen}
	command.Stdin, command.Stdout, command.Stderr = inputRead, outputWrite, io.Discard
	command.WaitDelay = 100 * time.Millisecond
	d := &deliveryState{owner: s, ctx: operation, cancel: cancel, command: command, input: inputWrite, output: outputRead, identity: identity, length: length, hash: sha256.New()}
	if err = operation.Err(); err == nil && !s.revoked.Load() {
		err = command.Start()
	} else {
		err = ErrDenied
	}
	_ = inputRead.Close()
	_ = outputWrite.Close()
	if err != nil {
		_ = inputWrite.Close()
		_ = outputRead.Close()
		cancel()
		s.mu.Unlock()
		return nil, ErrUnavailable
	}
	s.active.Store(d)
	s.mu.Unlock()
	keep := false
	defer func() {
		if !keep {
			_ = closeDelivery(&Delivery{state: d})
		}
	}()
	end, _ := operation.Deadline()
	if inputWrite.SetWriteDeadline(end) != nil || outputRead.SetReadDeadline(end) != nil {
		return nil, ErrUnsupported
	}
	// Revocation/cancellation also interrupts pipe IO even if a descendant retained a descriptor.
	context.AfterFunc(operation, func() { _ = inputWrite.Close(); _ = outputRead.Close() })
	copy(d.frame[:8], "SSINK001")
	if _, err = rand.Read(d.frame[8:24]); err != nil {
		return nil, ErrUnavailable
	}
	binding := bindingDigest(s.binding)
	copy(d.frame[24:56], binding[:])
	binary.BigEndian.PutUint64(d.frame[56:64], length)
	if checkPeer(command.Process.Pid, identity) != nil {
		return nil, ErrDenied
	}
	if err = writeExact(inputWrite, d.frame[:]); err != nil {
		return nil, ErrUnavailable
	}
	var ready [160]byte
	defer clear(ready[:])
	if _, err = io.ReadFull(outputRead, ready[:]); err != nil {
		return nil, ErrUnavailable
	}
	if string(ready[:8]) != "SSRDY001" || !bytes.Equal(ready[8:64], d.frame[8:]) || !bytes.Equal(ready[64:96], s.binding.Target[:]) || !bytes.Equal(ready[96:128], s.binding.Revision[:]) || !bytes.Equal(ready[128:160], s.binding.Purpose[:]) {
		return nil, ErrDenied
	}
	if checkConsumer(c, ref, encoded) != nil || checkPeer(command.Process.Pid, identity) != nil {
		return nil, ErrDenied
	}
	keep = true
	return &Delivery{state: d}, nil
}

func writeDelivery(delivery *Delivery, p []byte) (int, error) {
	if delivery == nil || delivery.state == nil {
		return 0, ErrDenied
	}
	d := delivery.state
	if !d.mu.TryLock() {
		return 0, ErrBusy
	}
	defer d.mu.Unlock()
	if d.closed.Load() || d.owner.revoked.Load() || !validBinding(d.owner.binding) || !time.Now().Before(d.owner.expires) {
		return 0, ErrDenied
	}
	if err := d.ctx.Err(); err != nil {
		return 0, err
	}
	if uint64(len(p)) > d.length-d.sent || len(p) > maxChunk {
		return 0, ErrInvalid
	}
	if checkPeer(d.command.Process.Pid, d.identity) != nil {
		return 0, ErrDenied
	}
	if len(p) == 0 {
		return 0, nil
	}
	d.possible = true
	n, err := d.input.Write(p)
	if n > 0 {
		_, _ = d.hash.Write(p[:n])
		d.sent += uint64(n)
	}
	if err != nil || n != len(p) {
		return n, ErrUnavailable
	}
	return n, nil
}

func finishDelivery(delivery *Delivery) (Result, error) {
	if delivery == nil || delivery.state == nil {
		return Result{}, ErrDenied
	}
	d := delivery.state
	if !d.mu.TryLock() {
		return Result{MayHaveDelivered: true}, ErrBusy
	}
	defer func() {
		if d.hash != nil {
			d.hash.Reset()
			d.hash = nil
		}
		d.mu.Unlock()
	}()
	result := Result{Bytes: d.sent, MayHaveDelivered: d.possible}
	if d.closed.Load() || d.owner.revoked.Load() || !validBinding(d.owner.binding) || !time.Now().Before(d.owner.expires) || d.ctx.Err() != nil || d.sent != d.length {
		stopDelivery(d)
		return result, ErrDenied
	}
	if d.input.Close() != nil {
		stopDelivery(d)
		return result, ErrUnavailable
	}
	var receipt [96]byte
	defer clear(receipt[:])
	if _, err := io.ReadFull(d.output, receipt[:]); err != nil {
		stopDelivery(d)
		return result, ErrUnavailable
	}
	var payloadHash [32]byte
	d.hash.Sum(payloadHash[:0])
	defer clear(payloadHash[:])
	if string(receipt[:8]) != "SSACK001" || !bytes.Equal(receipt[8:64], d.frame[8:]) || !bytes.Equal(receipt[64:], payloadHash[:]) {
		stopDelivery(d)
		return result, ErrDenied
	}
	var extra [1]byte
	if n, err := d.output.Read(extra[:]); n != 0 || err != io.EOF {
		stopDelivery(d)
		return result, ErrDenied
	}
	d.wait.Do(func() { d.waitErr = d.command.Wait() })
	if d.waitErr != nil || d.ctx.Err() != nil || d.owner.revoked.Load() || !validBinding(d.owner.binding) || !time.Now().Before(d.owner.expires) {
		stopDelivery(d)
		return result, ErrUnavailable
	}
	d.closed.Store(true)
	_ = d.output.Close()
	d.cancel()
	result.Complete = true
	return result, nil
}
func closeDelivery(delivery *Delivery) error {
	if delivery == nil || delivery.state == nil {
		return nil
	}
	d := delivery.state
	stopDelivery(d)
	d.mu.Lock()
	if d.hash != nil {
		d.hash.Reset()
		d.hash = nil
	}
	d.mu.Unlock()
	return nil
}
func stopDelivery(d *deliveryState) {
	d.closed.Store(true)
	d.cancel()
	_ = d.input.Close()
	_ = d.output.Close()
	d.wait.Do(func() { d.waitErr = d.command.Wait() })
}
func writeExact(f *os.File, p []byte) error {
	for len(p) > 0 {
		n, err := f.Write(p)
		if err != nil || n == 0 {
			return ErrUnavailable
		}
		p = p[n:]
	}
	return nil
}

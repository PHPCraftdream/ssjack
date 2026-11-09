//go:build linux && amd64

package appstorecrypto

import (
	"context"
	"crypto/subtle"
	"io"
	"sync/atomic"

	"github.com/PHPCraftdream/ssjack/internal/appstoretext"
	"github.com/PHPCraftdream/ssjack/internal/appstoretextstream"
)

type streamCountReader struct {
	ctx   context.Context
	input io.Reader
	check func() error
	bytes uint64
}

func (r *streamCountReader) Read(output []byte) (int, error) {
	if r.ctx.Err() != nil || r.check() != nil {
		return 0, ErrDelivery
	}
	n, err := r.input.Read(output)
	if n < 0 || n > len(output) || uint64(n) > appstoretextstream.MaxBytes-r.bytes {
		return 0, ErrDelivery
	}
	r.bytes += uint64(n)
	return n, err
}

type streamEOFReader struct {
	input io.Reader
	eof   atomic.Bool
}

func (r *streamEOFReader) Read(output []byte) (int, error) {
	n, err := r.input.Read(output)
	if err == io.EOF {
		r.eof.Store(true)
	}
	return n, err
}

func runTextStream(ctx context.Context, runner TextAdapterRunner, profile, command string, input io.ReadCloser, mappings []appstoretext.Mapping, binding *textBinding, ticket *textStreamTicket, check func() error) DeliveryOutcome {
	withheld := DeliveryOutcome{DeliveryWithheld}
	if ctx == nil || runner == nil || input == nil || ticket == nil || check == nil || ctx.Err() != nil || check() != nil {
		return withheld
	}
	probe, err := appstoretext.Replace(nil, mappings, false)
	clear(probe)
	if err != nil {
		return withheld
	}
	mac, err := newStreamTemplateMAC(binding, ticket.base)
	if err != nil {
		return withheld
	}
	pipeline, cancel := context.WithCancel(ctx)
	defer cancel()
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	stopWatch, watchDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(watchDone)
		select {
		case <-pipeline.Done():
			input.Close()
			writer.CloseWithError(ErrDelivery)
			reader.CloseWithError(ErrDelivery)
		case <-stopWatch:
		}
	}()
	transformed := make(chan error, 1)
	counted := &streamCountReader{ctx: pipeline, input: input, check: check}
	go func() {
		err := appstoretext.ReplaceStream(pipeline, io.TeeReader(counted, mac), writer, mappings, false, appstoretext.StreamLimits{Input: appstoretextstream.MaxBytes, Output: appstoretextstream.MaxBytes})
		if err == nil {
			actual := finishStreamTemplateMAC(mac, counted.bytes)
			if counted.bytes != ticket.bytes || subtle.ConstantTimeCompare(actual[:], ticket.mac[:]) != 1 {
				err = ErrDelivery
			}
			clear(actual[:])
		}
		if err != nil {
			_ = writer.CloseWithError(ErrDelivery)
		} else {
			_ = writer.Close()
		}
		transformed <- err
	}()
	consumed := &streamEOFReader{input: reader}
	exit, runErr := runner(pipeline, profile, command, consumed, io.Discard, io.Discard)
	if runErr != nil || exit != 0 || !consumed.eof.Load() || ctx.Err() != nil {
		cancel()
		input.Close()
		reader.CloseWithError(ErrDelivery)
		writer.CloseWithError(ErrDelivery)
	}
	transformErr := <-transformed
	close(stopWatch)
	<-watchDone
	if runErr != nil || exit != 0 || !consumed.eof.Load() || transformErr != nil || ctx.Err() != nil || check() != nil {
		return DeliveryOutcome{DeliveryUnknown}
	}
	return DeliveryOutcome{DeliveryReceived}
}

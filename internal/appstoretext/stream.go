package appstoretext

import (
	"bytes"
	"context"
	"io"
	"math"
)

const streamChunk = 32 << 10

type StreamLimits struct {
	Input  int64
	Output int64
}

// ReplaceStream writes tentative bytes only. The caller must not publish the
// sink before success; late ambiguity or I/O failure can leave partial output.
// Reader/writer cancellation is the caller's responsibility. Mappings are
// borrowed for this synchronous call. Memory is bounded by mapping sizes.
func ReplaceStream(ctx context.Context, input io.Reader, output io.Writer, mappings []Mapping, reverse bool, limits StreamLimits) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if input == nil || output == nil || limits.Input < 1 || limits.Input == math.MaxInt64 || limits.Output < 1 {
		return ErrInvalid
	}
	placeholders, tokens, err := prepareMappings(mappings, reverse)
	if err != nil {
		return err
	}
	lookahead, aggregate := 1, 0
	for i, token := range tokens {
		aggregate += len(mappings[i].Value)
		if aggregate > MaxText {
			return ErrInvalid
		}
		lookahead = max(lookahead, len(token), len(placeholders[i]))
	}
	guard := newStreamGuard(placeholders)
	defer clear(guard.tail[:cap(guard.tail)])
	buffer := make([]byte, lookahead+streamChunk)
	defer clear(buffer)
	writer := streamWriter{ctx: ctx, output: output, buffer: make([]byte, 0, streamChunk), limit: limits.Output}
	defer clear(writer.buffer[:cap(writer.buffer)])
	used, idle := 0, 0
	var read int64
	eof := false
	for {
		for !eof && used < len(buffer) {
			if err := ctx.Err(); err != nil {
				return err
			}
			available := min(int64(len(buffer)-used), limits.Input-read+1)
			n, readErr := input.Read(buffer[used : used+int(available)])
			if n < 0 || n > int(available) {
				return ErrInvalid
			}
			if reverse {
				if err := guard.accept(buffer[used : used+n]); err != nil {
					return err
				}
			}
			used, read = used+n, read+int64(n)
			if read > limits.Input {
				return ErrInvalid
			}
			if readErr != nil && readErr != io.EOF {
				return readErr
			}
			eof = readErr == io.EOF
			if n == 0 && !eof {
				idle++
				if idle == 100 {
					return io.ErrNoProgress
				}
			} else {
				idle = 0
			}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if used == 0 && eof {
			return writer.flush()
		}
		stop := used
		if !eof {
			stop = used - lookahead + 1
		}
		at := 0
		for at < stop {
			if err := ctx.Err(); err != nil {
				return err
			}
			best := -1
			for i, token := range tokens {
				if bytes.HasPrefix(buffer[at:used], token) && (best < 0 || len(token) > len(tokens[best])) {
					best = i
				}
			}
			if best < 0 {
				if err := writer.put(buffer[at : at+1]); err != nil {
					return err
				}
				at++
				continue
			}
			replacement := mappings[best].Value
			if reverse {
				replacement = placeholders[best]
			}
			if err := writer.put(replacement); err != nil {
				return err
			}
			at += len(tokens[best])
		}
		copy(buffer, buffer[at:used])
		clear(buffer[used-at : used])
		used -= at
	}
}

type streamWriter struct {
	ctx    context.Context
	output io.Writer
	buffer []byte
	limit  int64
	total  int64
}

func (w *streamWriter) put(data []byte) error {
	if int64(len(data)) > w.limit-w.total {
		return ErrInvalid
	}
	w.total += int64(len(data))
	for len(data) != 0 {
		n := min(len(data), cap(w.buffer)-len(w.buffer))
		w.buffer = append(w.buffer, data[:n]...)
		data = data[n:]
		if len(w.buffer) == cap(w.buffer) {
			if err := w.flush(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (w *streamWriter) flush() error {
	if err := w.ctx.Err(); err != nil {
		return err
	}
	if len(w.buffer) == 0 {
		return nil
	}
	n, err := w.output.Write(w.buffer)
	if err == nil && n != len(w.buffer) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = w.ctx.Err()
	}
	clear(w.buffer)
	w.buffer = w.buffer[:0]
	return err
}

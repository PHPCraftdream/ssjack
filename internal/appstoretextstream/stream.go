package appstoretextstream

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
)

func validStream(ctx context.Context, input io.Reader, output io.Writer, operation string, limit uint64) bool {
	return ctx != nil && input != nil && output != nil && validOperation(operation) && limit > 0 && limit <= MaxBytes
}

func Encode(ctx context.Context, input io.Reader, output io.Writer, operation string, limit uint64) error {
	if !validStream(ctx, input, output, operation, limit) {
		return ErrFrame
	}
	buffer := make([]byte, ChunkSize)
	defer clear(buffer)
	var total uint64
	var frames uint32
	filled, stalled := 0, 0
	flush := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if filled == 0 {
			return nil
		}
		if frames >= MaxFrames {
			return ErrFrame
		}
		encoded, err := encodeFrame(frame{Type: "data", OperationID: operation, Sequence: frames, Data: base64.StdEncoding.EncodeToString(buffer[:filled])})
		if err != nil {
			return err
		}
		defer clear(encoded)
		if err := writeAll(output, encoded); err != nil {
			return ErrFrame
		}
		clear(buffer[:filled])
		filled = 0
		frames++
		return ctx.Err()
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		available := buffer[filled:]
		if uint64(len(available)) > limit-total+1 {
			available = available[:int(limit-total+1)]
		}
		n, readErr := input.Read(available)
		if n < 0 || n > len(available) || uint64(n) > limit-total {
			return ErrFrame
		}
		if n == 0 && readErr == nil {
			stalled++
			if stalled >= 8 {
				return ErrFrame
			}
		} else {
			stalled = 0
		}
		filled += n
		total += uint64(n)
		if filled == ChunkSize {
			if err := flush(); err != nil {
				return err
			}
		}
		if readErr != nil {
			if readErr != io.EOF {
				return ErrFrame
			}
			break
		}
	}
	if err := flush(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	encoded, err := encodeFrame(frame{Type: "complete", OperationID: operation, Sequence: frames, Bytes: total, Frames: frames})
	if err != nil {
		return err
	}
	defer clear(encoded)
	if err := writeAll(output, encoded); err != nil {
		return ErrFrame
	}
	return ctx.Err()
}

type checkedReader struct {
	context context.Context
	input   io.Reader
}

func (r checkedReader) Read(output []byte) (int, error) {
	if err := r.context.Err(); err != nil {
		return 0, err
	}
	n, err := r.input.Read(output)
	if n < 0 || n > len(output) {
		return 0, ErrFrame
	}
	return n, err
}

func Decode(ctx context.Context, input io.Reader, output io.Writer, operation string, limit uint64) error {
	if !validStream(ctx, input, output, operation, limit) {
		return ErrFrame
	}
	reader := bufio.NewReaderSize(checkedReader{context: ctx, input: input}, MaxWireFrame+1)
	var wire uint64
	defer func() {
		if buffered := reader.Buffered(); buffered > 0 {
			data, _ := reader.Peek(buffered)
			clear(data)
		}
	}()
	var total uint64
	var frames uint32
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		line, err := reader.ReadSlice('\n')
		if err != nil || len(line) == 0 || len(line) > MaxWireFrame+1 {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return ErrFrame
		}
		wire += uint64(len(line))
		if wire > MaxWireBytes {
			return ErrFrame
		}
		value, err := decodeFrame(line[:len(line)-1])
		clear(line)
		if err != nil || value.OperationID != operation || value.Sequence != frames {
			return ErrFrame
		}
		if value.Type == "complete" {
			if value.Frames != frames || value.Bytes != total {
				return ErrFrame
			}
			if _, err := reader.ReadByte(); err != io.EOF {
				return ErrFrame
			}
			return ctx.Err()
		}
		if frames >= MaxFrames {
			return ErrFrame
		}
		decoded, err := decodeData(value.Data)
		if err != nil {
			return ErrFrame
		}
		if uint64(len(decoded)) > limit-total {
			clear(decoded)
			return ErrFrame
		}
		total += uint64(len(decoded))
		frames++
		if err := ctx.Err(); err != nil {
			clear(decoded)
			return err
		}
		writeErr := writeAll(output, decoded)
		clear(decoded)
		if writeErr != nil {
			return ErrFrame
		}
	}
}

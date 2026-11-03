package appstoretextstream

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"unicode/utf8"

	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
)

type templateReader struct {
	ctx     context.Context
	input   io.Reader
	limit   uint64
	total   uint64
	pending [utf8.UTFMax]byte
	used    int
}

func (r *templateReader) Read(output []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if uint64(len(output)) > r.limit-r.total+1 {
		output = output[:int(r.limit-r.total+1)]
	}
	n, err := r.input.Read(output)
	if n < 0 || n > len(output) || uint64(n) > r.limit-r.total {
		return 0, ErrFrame
	}
	for _, value := range output[:n] {
		if value == 0 {
			return 0, ErrFrame
		}
		if r.used == 0 && value < utf8.RuneSelf {
			continue
		}
		if r.used >= len(r.pending) {
			return 0, ErrFrame
		}
		r.pending[r.used] = value
		r.used++
		if utf8.FullRune(r.pending[:r.used]) {
			runeValue, size := utf8.DecodeRune(r.pending[:r.used])
			if runeValue == utf8.RuneError && size == 1 {
				return 0, ErrFrame
			}
			clear(r.pending[:])
			r.used = 0
		}
	}
	r.total += uint64(n)
	if err == io.EOF && r.used != 0 {
		return 0, ErrFrame
	}
	return n, err
}

func ValidateTemplate(ctx context.Context, input io.Reader, references []appstoreref.Ref, limit uint64) (uint64, error) {
	if ctx == nil || input == nil || len(references) == 0 || len(references) > 16 || limit == 0 || limit > MaxBytes {
		return 0, ErrFrame
	}
	placeholders := make([][]byte, len(references))
	lookahead := len("$ssjack")
	for i, reference := range references {
		encoded, err := appstoreplaceholder.Encode(reference)
		if err != nil {
			return 0, ErrFrame
		}
		if reference.StoreID() != references[0].StoreID() || reference.SnapshotID() != references[0].SnapshotID() {
			return 0, ErrFrame
		}
		for _, previous := range references[:i] {
			if previous == reference {
				return 0, ErrFrame
			}
		}
		placeholders[i] = encoded
		lookahead = max(lookahead, len(encoded))
	}
	checked := &templateReader{ctx: ctx, input: input, limit: limit}
	reader := bufio.NewReaderSize(checked, ChunkSize)
	defer func() {
		clear(checked.pending[:])
		if n := reader.Buffered(); n > 0 {
			data, _ := reader.Peek(n)
			clear(data)
		}
	}()
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		prefix, err := reader.Peek(lookahead)
		if err != nil && err != io.EOF {
			return 0, ErrFrame
		}
		if len(prefix) == 0 {
			if err != io.EOF || checked.used != 0 {
				return 0, ErrFrame
			}
			return checked.total, nil
		}
		consumed := 1
		matched := false
		for _, placeholder := range placeholders {
			if bytes.HasPrefix(prefix, placeholder) {
				consumed, matched = len(placeholder), true
				break
			}
		}
		if !matched && bytes.HasPrefix(prefix, []byte("$ssjack")) {
			return 0, ErrFrame
		}
		if _, err := reader.Discard(consumed); err != nil {
			return 0, ErrFrame
		}
	}
}

package ownerpacket

import (
	"context"
	"encoding/binary"
	"io"

	"github.com/PHPCraftdream/ssjack/internal/ownerlocal"
)

type frameReader struct {
	ctx        context.Context
	connection ownerlocal.Connection
}

func (r frameReader) Read(data []byte) (int, error) {
	n, err := r.connection.Read(r.ctx, data)
	if n < 0 || n > len(data) {
		return 0, ErrProtocol
	}
	if n == 0 && err == nil {
		return 0, io.ErrNoProgress
	}
	return n, err
}
func boundedContext(ctx context.Context) bool {
	if ctx == nil || ctx.Err() != nil {
		return false
	}
	_, bounded := ctx.Deadline()
	return bounded
}

// ReadFrame refuses the announced bound before allocating the ciphertext body.
func ReadFrame(ctx context.Context, connection ownerlocal.Connection) ([]byte, error) {
	if !boundedContext(ctx) || connection == nil {
		return nil, ErrProtocol
	}
	reader := frameReader{ctx, connection}
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, ErrProtocol
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > MaxWire {
		return nil, ErrProtocol
	}
	encoded := make([]byte, int(size))
	if _, err := io.ReadFull(reader, encoded); err != nil {
		clear(encoded)
		return nil, ErrProtocol
	}
	return encoded, nil
}

// A failed write never authorizes automatic replay of a possibly admitted command.
func WriteFrame(ctx context.Context, connection ownerlocal.Connection, encoded []byte) error {
	if !boundedContext(ctx) || connection == nil || len(encoded) == 0 || len(encoded) > MaxWire {
		return ErrProtocol
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(encoded)))
	for _, part := range [][]byte{header[:], encoded} {
		for len(part) != 0 {
			n, err := connection.Write(ctx, part)
			if err != nil || n <= 0 || n > len(part) {
				return ErrUncertain
			}
			part = part[n:]
		}
	}
	return nil
}

// Package driverframe implements bounded transport framing for proposed drivers.
// It deliberately does not decode JSON or validate driver schemas.
package driverframe

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const MaxPayload = 65536

var ErrLength = errors.New("driver frame length outside 1..65536")
var ErrTrailing = errors.New("trailing data after driver frame")
var ErrNoProgress = errors.New("driver frame transport made no progress")

// Read reads one frame. It allocates only after validating the four-byte length.
func Read(r io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := readFull(r, header[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(header[:])
	if n == 0 || n > MaxPayload {
		return nil, ErrLength
	}
	payload := make([]byte, int(n))
	if _, err := readFull(r, payload); err != nil {
		if err == io.EOF {
			return nil, io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return payload, nil
}

func readFull(r io.Reader, p []byte) (int, error) {
	read := 0
	stalls := 0
	for len(p) != 0 {
		n, err := r.Read(p)
		if n < 0 || n > len(p) {
			return read, fmt.Errorf("invalid read count %d", n)
		}
		if n > 0 {
			read += n
			p = p[n:]
			stalls = 0
		}
		if err != nil && err != io.EOF {
			return read, err
		}
		if len(p) == 0 {
			return read, nil
		}
		if err != nil {
			if err == io.EOF && read != 0 {
				return read, io.ErrUnexpectedEOF
			}
			return read, err
		}
		if n == 0 {
			stalls++
			if stalls >= 2 {
				return read, ErrNoProgress
			}
		}
	}
	return read, nil
}

// Write emits one frame, handling short writes and rejecting impossible or
// repeated zero-progress writes. Generic I/O may block; callers must supply a
// transport with suitable deadlines/cancellation or otherwise enforce them.
func Write(w io.Writer, payload []byte) error {
	if len(payload) == 0 || len(payload) > MaxPayload {
		return ErrLength
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if err := writeAll(w, header[:]); err != nil {
		return err
	}
	return writeAll(w, payload)
}

func writeAll(w io.Writer, p []byte) error {
	stalls := 0
	for len(p) != 0 {
		n, err := w.Write(p)
		if n < 0 || n > len(p) {
			return fmt.Errorf("invalid write count %d", n)
		}
		p = p[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			stalls++
			if stalls >= 2 {
				return ErrNoProgress
			}
		} else {
			stalls = 0
		}
	}
	return nil
}

// RequireEOF rejects another byte after the expected sole frame. It blocks
// until EOF or data and detects repeated zero-progress reads. Generic readers
// may block indefinitely; callers must close the producer and enforce deadlines.
func RequireEOF(r io.Reader) error {
	var b [1]byte
	stalls := 0
	for {
		n, err := r.Read(b[:])
		if n < 0 || n > 1 {
			return fmt.Errorf("invalid read count %d", n)
		}
		if n > 0 {
			return ErrTrailing
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		stalls++
		if stalls >= 2 {
			return ErrNoProgress
		}
	}
}

// Package appstorecatalog validates catalog structure, not snapshot authenticity.
package appstorecatalog

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/PHPCraftdream/ssjack/internal/appstoreheader"
)

const (
	Size       = 1 << 20
	MaxEntries = 16383
	prefixSize = 44
	entrySize  = 64
)

var ErrInvalid = errors.New("invalid application-store catalog")

type Entry struct {
	object  [16]byte
	version [16]byte
	length  uint64
	offset  uint64
	media   string
}

type Catalog struct {
	store    [16]byte
	snapshot [16]byte
	payload  uint64
	entries  []Entry
	parsed   bool
}

// Parse checks one complete catalog against a framing-admitted public header.
func Parse(header appstoreheader.Header, raw []byte) (Catalog, error) {
	if !header.Valid() || len(raw) != Size {
		return Catalog{}, ErrInvalid
	}
	b := append([]byte(nil), raw...)
	defer clear(b)
	if string(b[:8]) != "SSCAT001" || [16]byte(b[8:24]) != header.StoreID() || [16]byte(b[24:40]) != header.SnapshotID() {
		return Catalog{}, ErrInvalid
	}
	count := binary.BigEndian.Uint32(b[40:44])
	if count > MaxEntries {
		return Catalog{}, ErrInvalid
	}
	end := prefixSize + int(count)*entrySize
	if !zero(b[end:]) {
		return Catalog{}, ErrInvalid
	}
	payload := header.PlaintextSize() - Size
	entries := make([]Entry, 0, int(count))
	var cursor uint64
	var previous [32]byte
	for i := 0; i < int(count); i++ {
		start := prefixSize + i*entrySize
		row := b[start : start+entrySize]
		key := [32]byte(row[:32])
		object, version := [16]byte(row[:16]), [16]byte(row[16:32])
		if zero(object[:]) || zero(version[:]) || (i > 0 && bytes.Compare(key[:], previous[:]) <= 0) {
			return Catalog{}, ErrInvalid
		}
		length, offset := binary.BigEndian.Uint64(row[32:40]), binary.BigEndian.Uint64(row[40:48])
		if offset != cursor || length > payload-cursor {
			return Catalog{}, ErrInvalid
		}
		media, ok := mediaType(row[48:64])
		if !ok {
			return Catalog{}, ErrInvalid
		}
		entries = append(entries, Entry{object: object, version: version, length: length, offset: offset, media: media})
		cursor += length
		previous = key
	}
	if cursor != payload {
		return Catalog{}, ErrInvalid
	}
	return Catalog{store: header.StoreID(), snapshot: header.SnapshotID(), payload: payload, entries: entries, parsed: true}, nil
}

func zero(value []byte) bool {
	var bits byte
	for _, b := range value {
		bits |= b
	}
	return bits == 0
}

func mediaType(value []byte) (string, bool) {
	n := bytes.IndexByte(value, 0)
	if n < 1 || n > 15 || !zero(value[n:]) {
		return "", false
	}
	slash := false
	for i, b := range value[:n] {
		if b == '/' {
			if slash || i == 0 || i == n-1 {
				return "", false
			}
			slash = true
		} else if !(b >= 'a' && b <= 'z') && !(b >= '0' && b <= '9') && b != '.' && b != '+' && b != '-' {
			return "", false
		}
	}
	return string(value[:n]), true
}

func (c Catalog) Valid() bool          { return c.parsed }
func (c Catalog) StoreID() [16]byte    { return c.store }
func (c Catalog) SnapshotID() [16]byte { return c.snapshot }
func (c Catalog) PayloadSize() uint64  { return c.payload }
func (c Catalog) Entries() []Entry     { return append([]Entry(nil), c.entries...) }
func (e Entry) ObjectID() [16]byte     { return e.object }
func (e Entry) VersionID() [16]byte    { return e.version }
func (e Entry) Length() uint64         { return e.length }
func (e Entry) Offset() uint64         { return e.offset }
func (e Entry) MediaType() string      { return e.media }

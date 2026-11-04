package ownerarchive

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"sort"
	"strings"

	"github.com/PHPCraftdream/ssjack/internal/keyfile"
)

// ErrAuthentication means a wrong password or modified ciphertext; ErrArchive
// means a structurally invalid, unsupported or over-bound archive.
var ErrAuthentication = errors.New("owner archive authentication failed")

const (
	formatName  = "ssjack-owner-export-v1"
	maxSecrets  = 128
	maxEntries  = maxSecrets + 2
	maxValue    = 16384
	maxPath     = 4096
	maxPassword = 16 * 1024
)

// (128 values + database + manifest) * keyfile.MaxSize is about 32.5 MiB;
// the rest is ZIP overhead, rounded up.
const maxArchiveFile = 40 << 20

type unlockFunc func(manifestEncoded []byte) (plain []byte, open func([]byte) ([]byte, error), release func(), err error)

// Opened owns authenticated copies of an archive's contents until Close.
type Opened struct {
	encrypted bool
	database  []byte
	values    map[string][]byte
}

// ReadFile reads a regular file fully into memory; it never writes or extracts.
func ReadFile(ctx context.Context, path string, password []byte) (*Opened, error) {
	if ctx == nil || path == "" || len(path) > maxPath || strings.ContainsAny(path, "\x00\r\n") {
		return nil, ErrArchive
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// One no-follow, nonblocking open; the type is checked on the handle itself.
	file, err := openArchive(path)
	if err != nil {
		return nil, ErrArchive
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maxArchiveFile {
		return nil, ErrArchive
	}
	// Exact-size buffer: growing buffers would leave uncleared plaintext copies.
	data := make([]byte, info.Size())
	defer clear(data)
	limited := io.LimitReader(file, maxArchiveFile+1)
	if _, err := io.ReadFull(limited, data); err != nil {
		return nil, ErrArchive
	}
	var extra [1]byte
	if n, _ := limited.Read(extra[:]); n != 0 {
		return nil, ErrArchive
	}
	return Read(ctx, data, password)
}

// Read parses an archive held in memory. Plaintext archives ignore password.
func Read(ctx context.Context, data []byte, password []byte) (*Opened, error) {
	return read(ctx, data, func(manifest []byte) ([]byte, func([]byte) ([]byte, error), func(), error) {
		if len(password) == 0 || len(password) > maxPassword {
			return nil, nil, nil, ErrAuthentication
		}
		plain, unlocked, err := keyfile.Unlock(manifest, password)
		if err != nil {
			return nil, nil, nil, ErrAuthentication
		}
		return plain, unlocked.Open, unlocked.Close, nil
	})
}

func read(ctx context.Context, data []byte, unlock unlockFunc) (*Opened, error) {
	if ctx == nil || unlock == nil {
		return nil, ErrArchive
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Enforced here so every entry path (Read and ReadFile) keeps the memory bound.
	if len(data) > maxArchiveFile {
		return nil, ErrArchive
	}
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, ErrArchive
	}
	encrypted, files, err := classify(reader.File)
	if err != nil {
		return nil, err
	}
	manifestName := "manifest.json" + suffixFor(encrypted)
	manifestRaw, err := readEntry(files[manifestName], manifestName, encrypted)
	if err != nil {
		return nil, err
	}
	defer clear(manifestRaw)
	manifestPlain := manifestRaw
	// payloadOf always consumes raw: plaintext entries are kept as-is.
	payloadOf := func(raw []byte) ([]byte, error) { return raw, nil }
	if encrypted {
		plain, open, release, err := unlock(manifestRaw)
		if release != nil {
			defer release()
		}
		defer clear(plain)
		if err != nil || open == nil {
			return nil, ErrAuthentication
		}
		manifestPlain = plain
		payloadOf = func(raw []byte) ([]byte, error) {
			defer clear(raw)
			payload, err := open(raw)
			if err != nil {
				clear(payload)
				return nil, ErrAuthentication
			}
			return payload, nil
		}
	}
	m, err := parseManifest(manifestPlain, encrypted)
	if err != nil {
		return nil, err
	}
	if len(files) != len(m.Secrets)+2 {
		return nil, ErrArchive
	}
	o := &Opened{encrypted: encrypted, values: make(map[string][]byte, len(m.Secrets))}
	done := false
	defer func() {
		if !done {
			o.Close()
		}
	}()
	load := func(record fileRecord) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		raw, err := readEntry(files[record.Name], record.Name, encrypted)
		if err != nil {
			return nil, err
		}
		// Length and digest of the stored bytes are checked before decrypting.
		if !matches(raw, record) {
			clear(raw)
			if encrypted {
				return nil, ErrAuthentication
			}
			return nil, ErrArchive
		}
		return payloadOf(raw)
	}
	if o.database, err = load(m.Database); err != nil {
		return nil, err
	}
	refs, err := parseDatabase(o.database)
	if err != nil || len(refs) != len(m.Secrets) {
		return nil, ErrArchive
	}
	for id, record := range m.Secrets {
		if _, listed := refs[id]; !listed {
			return nil, ErrArchive
		}
		payload, err := load(record)
		if err != nil {
			return nil, err
		}
		value := payload
		if encrypted {
			if len(payload) == 0 || payload[0] != 1 {
				clear(payload)
				return nil, ErrArchive
			}
			value = payload[1:]
		}
		if len(value) > maxValue {
			clear(payload)
			return nil, ErrArchive
		}
		o.values[id] = value
	}
	done = true
	return o, nil
}

// readEntry checks the declared size against the entry's bound before opening,
// then reads exactly that many bytes (the final read verifies size and CRC).
func readEntry(f *zip.File, name string, encrypted bool) ([]byte, error) {
	bound := uint64(keyfile.MaxPlaintext)
	switch {
	case encrypted:
		bound = keyfile.MaxSize
	case strings.HasPrefix(name, "secrets/"):
		bound = maxValue
	}
	if f == nil || f.UncompressedSize64 > bound {
		return nil, ErrArchive
	}
	input, err := f.Open()
	if err != nil {
		return nil, ErrArchive
	}
	defer input.Close()
	buf := make([]byte, int(f.UncompressedSize64))
	limited := io.LimitReader(input, int64(bound)+1)
	var extra [1]byte
	if _, err := io.ReadFull(limited, buf); err != nil {
		clear(buf)
		return nil, ErrArchive
	}
	if n, err := limited.Read(extra[:]); n != 0 || err != io.EOF {
		clear(buf)
		return nil, ErrArchive
	}
	return buf, nil
}

func (o *Opened) Encrypted() bool { return o != nil && o.encrypted }

// Database is borrowed and valid until Close.
func (o *Opened) Database() []byte {
	if o == nil {
		return nil
	}
	return o.database
}

func (o *Opened) SecretIDs() []string {
	if o == nil {
		return nil
	}
	ids := make([]string, 0, len(o.values))
	for id := range o.values {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// Value is borrowed and valid until Close.
func (o *Opened) Value(id string) ([]byte, bool) {
	if o == nil {
		return nil, false
	}
	value, ok := o.values[id]
	return value, ok
}

func (o *Opened) Close() {
	if o == nil {
		return
	}
	clear(o.database)
	o.database = nil
	for id, value := range o.values {
		clear(value)
		delete(o.values, id)
	}
}

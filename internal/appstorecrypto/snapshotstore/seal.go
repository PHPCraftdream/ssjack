package snapshotstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"sort"
	"sync"

	"github.com/PHPCraftdream/ssjack/internal/appstorecatalog"
	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto/masterkey"
	"github.com/PHPCraftdream/ssjack/internal/appstorefile"
	"github.com/PHPCraftdream/ssjack/internal/appstoreheader"
)

func sealWriterSnapshot(m *masterkey.Master, ctx context.Context, header appstoreheader.Header, objects []writerObject, out io.Writer) ([32]byte, error) {
	var zeroHash [32]byte
	if ctx == nil || out == nil || !header.Valid() || !m.Matches(header) || len(objects) > appstorecatalog.MaxEntries {
		return zeroHash, masterkey.ErrRecord
	}
	catalog, total, err := writerCatalog(header, objects)
	if err != nil || total != header.PlaintextSize() {
		clear(catalog)
		return zeroHash, masterkey.ErrRecord
	}
	defer clear(catalog)
	for i := range objects {
		if err := ctx.Err(); err != nil {
			return zeroHash, err
		}
		if objects[i].source == nil {
			_, _ = objects[i].cursor.Seek(0, io.SeekStart)
			continue
		}
		if _, err := objects[i].source.Seek(0, io.SeekStart); err != nil {
			return zeroHash, masterkey.ErrRecord
		}
		if rev, err := appstorefile.Stat(objects[i].source); err != nil || rev != objects[i].revision {
			return zeroHash, masterkey.ErrRecord
		}
		if objects[i].revision.Size == 0 {
			var extra [1]byte
			got, e := objects[i].source.Read(extra[:])
			if got != 0 || !errors.Is(e, io.EOF) {
				return zeroHash, masterkey.ErrRecord
			}
			if rev, e := appstorefile.Stat(objects[i].source); e != nil || rev != objects[i].revision {
				return zeroHash, masterkey.ErrRecord
			}
		}
	}
	full, transcript := sha256.New(), sha256.New()
	write := func(p []byte, hash bool) error {
		n, e := out.Write(p)
		if e != nil {
			return e
		}
		if n != len(p) {
			return io.ErrShortWrite
		}
		if hash {
			_, _ = full.Write(p)
		}
		return nil
	}
	raw := header.Bytes()
	if err = write(raw[:], true); err != nil {
		return zeroHash, err
	}
	plain := make([]byte, appstoreheader.ChunkSize)
	defer clear(plain)
	sealed := make([]byte, 0, appstoreheader.ChunkSize+16000)
	defer func() {
		if sealed != nil {
			clear(sealed[:cap(sealed)])
		}
	}()
	objectIndex, objectOffset := 0, int64(0)
	for index := uint32(0); index < header.ChunkCount(); index++ {
		if err = ctx.Err(); err != nil {
			return zeroHash, err
		}
		n := appstoreheader.ChunkSize
		if rem := header.PlaintextSize() - uint64(index)*appstoreheader.ChunkSize; rem < uint64(n) {
			n = int(rem)
		}
		clear(plain)
		used := 0
		if index == 0 {
			copy(plain, catalog)
			used = len(catalog)
		}
		for used < n {
			for objectIndex < len(objects) && objectOffset == objects[objectIndex].revision.Size {
				objectIndex++
				objectOffset = 0
			}
			if objectIndex >= len(objects) {
				return zeroHash, masterkey.ErrRecord
			}
			remaining := objects[objectIndex].revision.Size - objectOffset
			if remaining == 0 {
				continue
			}
			count := n - used
			if int64(count) > remaining {
				count = int(remaining)
			}
			if err = ctx.Err(); err != nil {
				return zeroHash, err
			}
			got, e := io.ReadFull(writerObjectReader(&objects[objectIndex]), plain[used:used+count])
			if e != nil || got != count {
				return zeroHash, masterkey.ErrRecord
			}
			used += count
			objectOffset += int64(count)
			if objectOffset == objects[objectIndex].revision.Size {
				var extra [1]byte
				got, e = writerObjectReader(&objects[objectIndex]).Read(extra[:])
				if got != 0 || !errors.Is(e, io.EOF) {
					return zeroHash, masterkey.ErrRecord
				}
				if objects[objectIndex].source != nil {
					if rev, e := appstorefile.Stat(objects[objectIndex].source); e != nil || rev != objects[objectIndex].revision {
						return zeroHash, masterkey.ErrRecord
					}
				}
				objectIndex++
				objectOffset = 0
			}
		}
		sealed, err = masterkey.SealRecord(m, ctx, header, index, false, plain[:n])
		if err != nil {
			return zeroHash, err
		}
		var prefix [12]byte
		binary.BigEndian.PutUint32(prefix[:4], index)
		binary.BigEndian.PutUint32(prefix[4:8], uint32(n))
		binary.BigEndian.PutUint32(prefix[8:12], uint32(len(sealed)))
		if err = write(prefix[:], true); err != nil {
			return zeroHash, err
		}
		if err = write(sealed, true); err != nil {
			return zeroHash, err
		}
		_, _ = transcript.Write(prefix[:])
		_, _ = transcript.Write(sealed)
		clear(sealed)
		sealed = sealed[:0]
	}
	for objectIndex < len(objects) {
		if err = ctx.Err(); err != nil {
			return zeroHash, err
		}
		if objectOffset != 0 || objects[objectIndex].revision.Size != 0 {
			return zeroHash, masterkey.ErrRecord
		}
		var extra [1]byte
		got, e := writerObjectReader(&objects[objectIndex]).Read(extra[:])
		if got != 0 || !errors.Is(e, io.EOF) {
			return zeroHash, masterkey.ErrRecord
		}
		if objects[objectIndex].source != nil {
			if rev, e := appstorefile.Stat(objects[objectIndex].source); e != nil || rev != objects[objectIndex].revision {
				return zeroHash, masterkey.ErrRecord
			}
		}
		objectIndex++
	}
	for _, object := range objects {
		if object.source != nil {
			if rev, e := appstorefile.Stat(object.source); e != nil || rev != object.revision {
				return zeroHash, masterkey.ErrRecord
			}
		}
	}
	var final [48]byte
	copy(final[:4], "FIN1")
	binary.BigEndian.PutUint64(final[4:12], header.PlaintextSize())
	binary.BigEndian.PutUint32(final[12:16], header.ChunkCount())
	copy(final[16:], transcript.Sum(nil))
	sealed, err = masterkey.SealRecord(m, ctx, header, ^uint32(0), true, final[:])
	clear(final[:])
	if err != nil {
		return zeroHash, err
	}
	var foot [12]byte
	copy(foot[:4], "FIN1")
	binary.BigEndian.PutUint64(foot[4:], uint64(len(sealed)))
	if err = write(foot[:], true); err == nil {
		err = write(sealed, true)
	}
	clear(sealed)
	if err != nil {
		return zeroHash, err
	}
	var result [32]byte
	copy(result[:], full.Sum(nil))
	return result, nil
}

type writerObject struct {
	id, version [16]byte
	media       string
	source      *os.File
	memory      []byte
	cursor      *bytes.Reader
	revision    appstorefile.Revision
}

func prepareWriterObjects(ctx context.Context, input []SnapshotObject) ([]writerObject, uint64, error) {
	if ctx == nil || len(input) > appstorecatalog.MaxEntries {
		return nil, 0, masterkey.ErrRecord
	}
	out := make([]writerObject, len(input))
	seen := make(map[[16]byte]bool, len(input))
	seenSources := make(map[[2]uint64]struct{}, len(input))
	seenMemory := make(map[*ramSource]bool, len(input))
	var payload uint64
	var ramBytes int
	success := false
	defer func() {
		if !success {
			for i := range out {
				clear(out[i].memory)
			}
		}
	}()
	for i, item := range input {
		if err := ctx.Err(); err != nil {
			return nil, 0, err
		}
		if (item.Source == nil) == (item.memory == nil) {
			return nil, 0, masterkey.ErrRecord
		}
		var memory []byte
		if item.memory != nil {
			var e error
			memory, e = item.memory.takeCopy()
			if e != nil {
				return nil, 0, masterkey.ErrRecord
			}
			ramBytes += len(memory)
			if ramBytes > 8<<20 {
				clear(memory)
				return nil, 0, masterkey.ErrRecord
			}
			out[i].memory = memory
		}
		if item.ObjectID == ([16]byte{}) || seen[item.ObjectID] || !validMedia(item.MediaType) {
			clear(memory)
			return nil, 0, masterkey.ErrRecord
		}
		seen[item.ObjectID] = true
		var rev appstorefile.Revision
		var err error
		if item.Source != nil {
			rev, err = appstorefile.Stat(item.Source)
		} else {
			rev.Size = int64(len(memory))
		}
		if err != nil || rev.Size < 0 || uint64(rev.Size) > appstoreheader.MaxPlaintext-appstorecatalog.Size-payload {
			return nil, 0, masterkey.ErrRecord
		}
		if item.memory != nil {
			if seenMemory[item.memory] {
				clear(memory)
				return nil, 0, masterkey.ErrRecord
			}
			seenMemory[item.memory] = true
		} else {
			sourceID := [2]uint64{rev.Dev, rev.Ino}
			if _, duplicate := seenSources[sourceID]; duplicate {
				clear(memory)
				return nil, 0, masterkey.ErrRecord
			}
			seenSources[sourceID] = struct{}{}
		}
		var version [16]byte
		for version == ([16]byte{}) {
			if _, err = rand.Read(version[:]); err != nil {
				return nil, 0, err
			}
		}
		out[i] = writerObject{id: item.ObjectID, version: version, media: item.MediaType, source: item.Source, memory: memory, cursor: bytes.NewReader(memory), revision: rev}
		payload += uint64(rev.Size)
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i].id[:], out[j].id[:]) < 0 })
	success = true
	return out, appstorecatalog.Size + payload, nil
}

func writerObjectReader(o *writerObject) io.Reader {
	if o.source != nil {
		return o.source
	}
	return o.cursor
}

func writerCatalog(h appstoreheader.Header, objects []writerObject) ([]byte, uint64, error) {
	if !h.Valid() || len(objects) > appstorecatalog.MaxEntries {
		return nil, 0, masterkey.ErrRecord
	}
	b := make([]byte, appstorecatalog.Size)
	copy(b[:8], "SSCAT001")
	store, snapshot := h.StoreID(), h.SnapshotID()
	copy(b[8:24], store[:])
	copy(b[24:40], snapshot[:])
	binary.BigEndian.PutUint32(b[40:44], uint32(len(objects)))
	var offset uint64
	for i, o := range objects {
		if (o.source == nil) == (o.memory == nil) || o.id == ([16]byte{}) || o.version == ([16]byte{}) || !validMedia(o.media) || (i > 0 && bytes.Compare(objects[i-1].id[:], o.id[:]) >= 0) {
			return b, 0, masterkey.ErrRecord
		}
		if o.source == nil {
			_, _ = o.cursor.Seek(0, io.SeekStart)
		}
		if o.source != nil {
			r, e := appstorefile.Stat(o.source)
			if e != nil || r != o.revision {
				return b, 0, masterkey.ErrRecord
			}
		}
		r := o.revision
		if r.Size < 0 {
			return b, 0, masterkey.ErrRecord
		}
		size := uint64(r.Size)
		if size > appstoreheader.MaxPlaintext-appstorecatalog.Size-offset {
			return b, 0, masterkey.ErrRecord
		}
		row := b[44+i*64 : 44+(i+1)*64]
		copy(row[:16], o.id[:])
		copy(row[16:32], o.version[:])
		binary.BigEndian.PutUint64(row[32:40], size)
		binary.BigEndian.PutUint64(row[40:48], offset)
		copy(row[48:64], o.media)
		offset += size
	}
	if offset > appstoreheader.MaxPlaintext-appstorecatalog.Size {
		return b, 0, masterkey.ErrRecord
	}
	// Parse enforces the exact canonical catalog and payload accounting.
	if _, e := appstorecatalog.Parse(h, b); e != nil {
		return b, 0, e
	}
	return b, appstorecatalog.Size + offset, nil
}

// MaxRAMSecretSize is the largest secret NewSecretObject accepts.
const MaxRAMSecretSize = 16384

const maxRAMSecretSize = MaxRAMSecretSize

// ramSource owns bounded bytes; clearing is best-effort and does not guarantee host-swap protection.
type ramSource struct {
	mu     sync.Mutex
	data   []byte
	closed bool
}

func (r *ramSource) takeCopy() ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.data == nil {
		return nil, masterkey.ErrClosed
	}
	copyBytes := make([]byte, len(r.data))
	copy(copyBytes, r.data)
	return copyBytes, nil
}
func (r *ramSource) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	clear(r.data)
	r.data = nil
	r.closed = true
	r.mu.Unlock()
}

// NewSecretObject copies a secret of at most 16 KiB into writer-owned RAM.
// Its returned close function clears that owned copy; host swap is outside this guarantee.
func NewSecretObject(objectID [16]byte, media string, secret []byte) (SnapshotObject, func(), error) {
	if objectID == ([16]byte{}) || !validMedia(media) || len(secret) > maxRAMSecretSize {
		return SnapshotObject{}, nil, masterkey.ErrRecord
	}
	r := &ramSource{data: append([]byte(nil), secret...)}
	if r.data == nil {
		r.data = make([]byte, 0)
	}
	return SnapshotObject{ObjectID: objectID, MediaType: media, memory: r}, r.Close, nil
}

// NewSecretObjectUnbounded is a test seam that bypasses NewSecretObject's size limit.
func NewSecretObjectUnbounded(objectID [16]byte, media string, secret []byte) (SnapshotObject, func()) {
	r := &ramSource{data: append([]byte(nil), secret...)}
	return SnapshotObject{ObjectID: objectID, MediaType: media, memory: r}, r.Close
}

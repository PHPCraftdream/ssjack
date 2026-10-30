package appstorecrypto

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"sort"

	"github.com/PHPCraftdream/ssjack/internal/appstorecatalog"
	"github.com/PHPCraftdream/ssjack/internal/appstorefile"
	"github.com/PHPCraftdream/ssjack/internal/appstoreheader"
	"golang.org/x/crypto/hkdf"
)

const recordLayers = 1000

var ErrRecord = errors.New("invalid application-store record context")
var ErrClosed = errors.New("application-store master closed or unavailable")
var ErrBusy = errors.New("application-store master operation busy")
var ErrAuthentication = errors.New("application-store record authentication failed")

// These primitives stay private until reservation and full-snapshot release gates exist.
func (m *Master) sealRecord(ctx context.Context, h appstoreheader.Header, index uint32, final bool, plaintext []byte) ([]byte, error) {
	return m.transformRecord(ctx, h, index, final, plaintext, true, nil)
}
func (m *Master) openRecord(ctx context.Context, h appstoreheader.Header, index uint32, final bool, ciphertext []byte) ([]byte, error) {
	return m.transformRecord(ctx, h, index, final, ciphertext, false, nil)
}

func (m *Master) sealWriterSnapshot(ctx context.Context, header appstoreheader.Header, objects []writerObject, out io.Writer) ([32]byte, error) {
	var zeroHash [32]byte
	if ctx == nil || out == nil || !header.Valid() || !m.Matches(header) || len(objects) > appstorecatalog.MaxEntries {
		return zeroHash, ErrRecord
	}
	catalog, total, err := writerCatalog(header, objects)
	if err != nil || total != header.PlaintextSize() {
		clear(catalog)
		return zeroHash, ErrRecord
	}
	defer clear(catalog)
	for i := range objects {
		if err := ctx.Err(); err != nil {
			return zeroHash, err
		}
		if _, err := objects[i].source.Seek(0, io.SeekStart); err != nil {
			return zeroHash, ErrRecord
		}
		if rev, err := appstorefile.Stat(objects[i].source); err != nil || rev != objects[i].revision {
			return zeroHash, ErrRecord
		}
		if objects[i].revision.Size == 0 {
			var extra [1]byte
			got, e := objects[i].source.Read(extra[:])
			if got != 0 || !errors.Is(e, io.EOF) {
				return zeroHash, ErrRecord
			}
			if rev, e := appstorefile.Stat(objects[i].source); e != nil || rev != objects[i].revision {
				return zeroHash, ErrRecord
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
				return zeroHash, ErrRecord
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
			got, e := io.ReadFull(objects[objectIndex].source, plain[used:used+count])
			if e != nil || got != count {
				return zeroHash, ErrRecord
			}
			used += count
			objectOffset += int64(count)
			if objectOffset == objects[objectIndex].revision.Size {
				var extra [1]byte
				got, e = objects[objectIndex].source.Read(extra[:])
				if got != 0 || !errors.Is(e, io.EOF) {
					return zeroHash, ErrRecord
				}
				if rev, e := appstorefile.Stat(objects[objectIndex].source); e != nil || rev != objects[objectIndex].revision {
					return zeroHash, ErrRecord
				}
				objectIndex++
				objectOffset = 0
			}
		}
		sealed, err = m.sealRecord(ctx, header, index, false, plain[:n])
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
			return zeroHash, ErrRecord
		}
		var extra [1]byte
		got, e := objects[objectIndex].source.Read(extra[:])
		if got != 0 || !errors.Is(e, io.EOF) {
			return zeroHash, ErrRecord
		}
		if rev, e := appstorefile.Stat(objects[objectIndex].source); e != nil || rev != objects[objectIndex].revision {
			return zeroHash, ErrRecord
		}
		objectIndex++
	}
	for _, object := range objects {
		if rev, e := appstorefile.Stat(object.source); e != nil || rev != object.revision {
			return zeroHash, ErrRecord
		}
	}
	var final [48]byte
	copy(final[:4], "FIN1")
	binary.BigEndian.PutUint64(final[4:12], header.PlaintextSize())
	binary.BigEndian.PutUint32(final[12:16], header.ChunkCount())
	copy(final[16:], transcript.Sum(nil))
	sealed, err = m.sealRecord(ctx, header, ^uint32(0), true, final[:])
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
	revision    appstorefile.Revision
}

func prepareWriterObjects(ctx context.Context, input []SnapshotObject) ([]writerObject, uint64, error) {
	if ctx == nil || len(input) > appstorecatalog.MaxEntries {
		return nil, 0, ErrRecord
	}
	out := make([]writerObject, len(input))
	seen := make(map[[16]byte]bool, len(input))
	seenSources := make(map[[2]uint64]struct{}, len(input))
	var payload uint64
	for i, item := range input {
		if err := ctx.Err(); err != nil {
			return nil, 0, err
		}
		if item.ObjectID == ([16]byte{}) || seen[item.ObjectID] || item.Source == nil || !validMedia(item.MediaType) {
			return nil, 0, ErrRecord
		}
		seen[item.ObjectID] = true
		rev, err := appstorefile.Stat(item.Source)
		if err != nil || rev.Size < 0 || uint64(rev.Size) > appstoreheader.MaxPlaintext-appstorecatalog.Size-payload {
			return nil, 0, ErrRecord
		}
		sourceID := [2]uint64{rev.Dev, rev.Ino}
		if _, duplicate := seenSources[sourceID]; duplicate {
			return nil, 0, ErrRecord
		}
		seenSources[sourceID] = struct{}{}
		var version [16]byte
		for version == ([16]byte{}) {
			if _, err = rand.Read(version[:]); err != nil {
				return nil, 0, err
			}
		}
		out[i] = writerObject{id: item.ObjectID, version: version, media: item.MediaType, source: item.Source, revision: rev}
		payload += uint64(rev.Size)
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i].id[:], out[j].id[:]) < 0 })
	return out, appstorecatalog.Size + payload, nil
}

func writerCatalog(h appstoreheader.Header, objects []writerObject) ([]byte, uint64, error) {
	if !h.Valid() || len(objects) > appstorecatalog.MaxEntries {
		return nil, 0, ErrRecord
	}
	b := make([]byte, appstorecatalog.Size)
	copy(b[:8], "SSCAT001")
	store, snapshot := h.StoreID(), h.SnapshotID()
	copy(b[8:24], store[:])
	copy(b[24:40], snapshot[:])
	binary.BigEndian.PutUint32(b[40:44], uint32(len(objects)))
	var offset uint64
	for i, o := range objects {
		if o.source == nil || o.id == ([16]byte{}) || o.version == ([16]byte{}) || !validMedia(o.media) || (i > 0 && bytes.Compare(objects[i-1].id[:], o.id[:]) >= 0) {
			return b, 0, ErrRecord
		}
		r, e := appstorefile.Stat(o.source)
		if e != nil || r != o.revision || r.Size < 0 {
			return b, 0, ErrRecord
		}
		size := uint64(r.Size)
		if size > appstoreheader.MaxPlaintext-appstorecatalog.Size-offset {
			return b, 0, ErrRecord
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
		return b, 0, ErrRecord
	}
	// Parse enforces the exact canonical catalog and payload accounting.
	if _, e := appstorecatalog.Parse(h, b); e != nil {
		return b, 0, e
	}
	return b, appstorecatalog.Size + offset, nil
}

func recordLength(h appstoreheader.Header, index uint32, final bool) (int, error) {
	if !h.Valid() {
		return 0, ErrRecord
	}
	if final {
		if index != ^uint32(0) {
			return 0, ErrRecord
		}
		return 48, nil
	}
	if index >= h.ChunkCount() {
		return 0, ErrRecord
	}
	remaining := h.PlaintextSize() - uint64(index)*appstoreheader.ChunkSize
	if remaining > appstoreheader.ChunkSize {
		remaining = appstoreheader.ChunkSize
	}
	return int(remaining), nil
}

func finalPlain(h appstoreheader.Header, data []byte) bool {
	return len(data) == 48 && string(data[:4]) == "FIN1" && binary.BigEndian.Uint64(data[4:12]) == h.PlaintextSize() && binary.BigEndian.Uint32(data[12:16]) == h.ChunkCount()
}

func (m *Master) transformRecord(ctx context.Context, h appstoreheader.Header, index uint32, final bool, input []byte, sealing bool, observe func(uint32)) ([]byte, error) {
	plain, err := recordLength(h, index, final)
	if err != nil || ctx == nil {
		return nil, ErrRecord
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ciphertext := plain + recordLayers*16
	want := ciphertext
	if sealing {
		want = plain
	}
	if len(input) != want {
		return nil, ErrRecord
	}
	if m == nil || m.state == nil {
		return nil, ErrClosed
	}
	if !m.state.mu.TryLock() {
		return nil, ErrBusy
	}
	defer m.state.mu.Unlock()
	if !m.state.ready {
		return nil, ErrClosed
	}
	if m.state.store != h.StoreID() || m.state.salts != h.Salts() {
		return nil, ErrRecord
	}
	data := make([]byte, len(input), ciphertext)
	copy(data, input)
	complete := false
	defer func() {
		if !complete {
			clear(data[:cap(data)])
		}
	}()
	if sealing && final && !finalPlain(h, data) {
		return nil, ErrRecord
	}
	for step := 0; step < recordLayers; step++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		layer := uint32(step)
		if !sealing {
			layer = uint32(recordLayers - 1 - step)
		}
		aead, nonce, aad, err := recordLayer(m.state.key[:], h, index, layer, final, uint32(plain), uint32(ciphertext))
		if err != nil {
			return nil, ErrDerivation
		}
		if sealing {
			data = aead.Seal(data[:0], nonce[:], data, aad)
		} else {
			opened, err := aead.Open(data[:0], nonce[:], data, aad)
			if err != nil {
				return nil, ErrAuthentication
			}
			clear(data[len(opened):])
			data = opened
		}
		if observe != nil {
			observe(layer)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !sealing && final && !finalPlain(h, data) {
		return nil, ErrRecord
	}
	complete = true
	return data, nil
}

func recordLayer(master []byte, h appstoreheader.Header, index, layer uint32, final bool, plain, ciphertext uint32) (cipher.AEAD, [12]byte, []byte, error) {
	if len(master) != 32 || layer >= recordLayers {
		return nil, [12]byte{}, nil, ErrRecord
	}
	contextDomain, nonceDomain, label := "ssjack-appstore/v1/data/chunk/", "ssjack-appstore/v1/nonce", "SSAPP chunk layer"
	if final {
		contextDomain, nonceDomain, label = "ssjack-appstore/v1/data/final/", "ssjack-appstore/v1/nonce/final", "SSAPP final layer"
	}
	store, snapshot, base := h.StoreID(), h.SnapshotID(), h.NonceBase()
	contextBytes := append([]byte(contextDomain), store[:]...)
	contextBytes = append(contextBytes, snapshot[:]...)
	contextBytes = binary.BigEndian.AppendUint32(contextBytes, index)
	contextBytes = binary.BigEndian.AppendUint32(contextBytes, layer)
	var key [32]byte
	defer clear(key[:])
	if _, err := io.ReadFull(hkdf.New(sha256.New, master, nil, contextBytes), key[:]); err != nil {
		return nil, [12]byte{}, nil, err
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, [12]byte{}, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, [12]byte{}, nil, err
	}
	nonceInput := append([]byte(nonceDomain), store[:]...)
	nonceInput = append(nonceInput, snapshot[:]...)
	nonceInput = binary.BigEndian.AppendUint32(nonceInput, index)
	nonceInput = binary.BigEndian.AppendUint32(nonceInput, layer)
	mac := hmac.New(sha256.New, base[:])
	_, _ = mac.Write(nonceInput)
	nonceSum := mac.Sum(nil)
	var nonce [12]byte
	copy(nonce[:], nonceSum[:12])
	clear(nonceSum)
	header := h.Bytes()
	aad := append([]byte(nil), header[:]...)
	aad = binary.BigEndian.AppendUint32(aad, index)
	aad = binary.BigEndian.AppendUint32(aad, layer)
	aad = binary.BigEndian.AppendUint32(aad, plain)
	aad = binary.BigEndian.AppendUint32(aad, ciphertext)
	aad = append(aad, label...)
	return aead, nonce, aad, nil
}

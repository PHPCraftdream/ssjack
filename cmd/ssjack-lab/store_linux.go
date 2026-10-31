//go:build linux && amd64

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorreply"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorstate"
	"github.com/PHPCraftdream/ssjack/internal/appstoreheader"
	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
)

func (l *deliveryLab) storeSetup() error {
	enc := func(b []byte) []byte { return []byte(base64.StdEncoding.EncodeToString(b)) }
	fingerprint := func(b []byte) []byte { s := sha256.Sum256(b); return []byte(hex.EncodeToString(s[:])) }
	chain := []string{base64.StdEncoding.EncodeToString(l.anchor.clientChain[0]), base64.StdEncoding.EncodeToString(l.anchor.clientChain[1])}
	store := hex.EncodeToString(l.anchor.store[:])
	answers := []labAnswer{{"Exact HTTPS anchor endpoint: ", []byte(l.anchor.endpoint)}, {"Repeat exact endpoint from independent source: ", []byte(l.anchor.endpoint)}, {"Existing storeID (32 hex characters): ", []byte(store)}, {"Repeat exact storeID from independent source: ", []byte(store)}, {"Anchor signing public key raw 32-byte base64: ", enc(l.anchor.serviceKey)}, {"Repeat signing public key from independent source: ", enc(l.anchor.serviceKey)}, {"CA certificate DER base64 (one root only): ", enc(l.anchor.caDER)}, {"Client certificate chain DER base64 (leaf first, max 8): ", []byte(strings.Join(chain, ","))}, {"CA SHA256 fingerprint from independent source: ", fingerprint(l.anchor.caDER)}, {"Client leaf SHA256 fingerprint from independent source: ", fingerprint(l.anchor.clientChain[0])}, {"Client PKCS#8 private key DER base64: ", enc(l.anchor.privateDER)}, {"New application-store master secret: ", l.master}, {"Confirm application-store master secret: ", l.master}}
	if _, e := l.cli(labUID, answers, "appstore", "setup", l.root); e != nil {
		return e
	}
	out, e := l.cli(labUID, []labAnswer{{"Application-store master secret: ", l.master}, {"Secret (max 16 KiB): ", l.payload}}, "appstore", "put", l.root)
	if e != nil {
		return e
	}
	ref := strings.SplitN(out, "\n", 2)[0]
	r, e := appstoreplaceholder.Parse([]byte(ref))
	if e != nil || !r.Valid() || r.StoreID() != l.anchor.store {
		return errors.New("reference mismatch")
	}
	canon, e := appstoreplaceholder.Encode(r)
	if e != nil || !bytes.Equal(canon, []byte(ref)) {
		return errors.New("reference not canonical")
	}
	l.ref = ref
	binding, e := os.Open(filepath.Join(l.root, "binding.bin"))
	if e != nil {
		return e
	}
	installHash, e := hashRecipientFile(binding)
	ce := binding.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	l.installationHash = installHash
	rootInfo, e := os.Stat(l.root)
	if e != nil {
		return e
	}
	rootStat, ok := rootInfo.Sys().(*syscall.Stat_t)
	if !ok || rootStat.Uid != labUID || rootStat.Mode&07777 != 0700 {
		return errors.New("store owner/mode mismatch")
	}
	id := r.SnapshotID()
	snapshotPath := filepath.Join(l.root, "snapshots", hex.EncodeToString(id[:])+".bin")
	snapshot, e := os.Open(snapshotPath)
	if e != nil {
		return e
	}
	actual, e := hashRecipientFile(snapshot)
	if e != nil {
		_ = snapshot.Close()
		return e
	}
	if _, e = snapshot.Seek(0, io.SeekStart); e != nil {
		_ = snapshot.Close()
		return e
	}
	var raw [appstoreheader.Size]byte
	if _, e = io.ReadFull(snapshot, raw[:]); e != nil {
		_ = snapshot.Close()
		return e
	}
	header, e := appstoreheader.Parse(raw[:])
	clear(raw[:])
	ce = snapshot.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	if !header.Valid() || header.StoreID() != l.anchor.store || header.SnapshotID() != id {
		return errors.New("snapshot header mismatch")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	reply, e := l.anchor.transport.Read(ctx)
	if e != nil {
		return e
	}
	state, ok := reply.State()
	if !ok || !reply.SignatureValid() || reply.Outcome() != appstoreanchorreply.ReadState || reply.Operation() != appstoreanchorreply.Read || state.Sequence() != 1 {
		return errors.New("anchor read mismatch")
	}
	genesis, e := appstoreanchorstate.Genesis(l.anchor.store)
	if e != nil || state == genesis || state.StoreID() != l.anchor.store || state.JournalCount() == 0 {
		return errors.New("anchor genesis mismatch")
	}
	actualBytes, e := hex.DecodeString(actual)
	committedHash := state.CommittedFileHash()
	if e != nil || len(actualBytes) != 32 || !bytes.Equal(actualBytes, committedHash[:]) || state.CommittedSnapshotID() != id {
		return errors.New("ciphertext differs from anchor")
	}
	pointer, e := os.Open(filepath.Join(l.root, "pointer.bin"))
	if e != nil {
		return e
	}
	pi, e := pointer.Stat()
	if e != nil {
		_ = pointer.Close()
		return e
	}
	ps, ok := pi.Sys().(*syscall.Stat_t)
	if !ok || ps.Uid != labUID || ps.Mode&07777 != 0600 || ps.Nlink != 1 || ps.Size != 64 {
		_ = pointer.Close()
		return errors.New("pointer metadata invalid")
	}
	var tuple [64]byte
	_, e = io.ReadFull(pointer, tuple[:])
	ce = pointer.Close()
	if e != nil || ce != nil {
		return errors.New("pointer read failed")
	}
	snapshotID, txnID := state.CommittedSnapshotID(), state.CommittedTransactionID()
	var want [64]byte
	copy(want[:16], snapshotID[:])
	copy(want[16:48], committedHash[:])
	copy(want[48:], txnID[:])
	if tuple != want {
		return errors.New("pointer/anchor mismatch")
	}
	l.encodedHash = actual
	return nil
}
func hashRecipientFile(f *os.File) (string, error) {
	before, e := f.Stat()
	if e != nil {
		return "", e
	}
	st, ok := before.Sys().(*syscall.Stat_t)
	if !ok || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Uid != labUID || st.Mode&07777 != 0600 || st.Nlink != 1 || st.Size < 1 || st.Size > 1<<30 {
		return "", errors.New("file owner/mode invalid")
	}
	if _, e = f.Seek(0, io.SeekStart); e != nil {
		return "", e
	}
	h := sha256.New()
	n, e := io.CopyN(h, f, st.Size)
	if e != nil || n != st.Size {
		return "", errors.New("bounded file read failed")
	}
	var extra [1]byte
	if extraN, extraErr := f.Read(extra[:]); extraN != 0 || extraErr != io.EOF {
		return "", errors.New("file length changed")
	}
	after, e := f.Stat()
	if e != nil {
		return "", e
	}
	a, ok := after.Sys().(*syscall.Stat_t)
	if !ok || a.Dev != st.Dev || a.Ino != st.Ino || a.Uid != st.Uid || a.Mode != st.Mode || a.Nlink != st.Nlink || a.Size != st.Size || a.Mtim != st.Mtim || a.Ctim != st.Ctim {
		return "", errors.New("file changed while hashing")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func (l *deliveryLab) scanCiphertext() error {
	return filepath.WalkDir(l.root, func(path string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if !d.Type().IsRegular() {
			return nil
		}
		f, e := os.Open(path)
		if e != nil {
			return e
		}
		info, e := f.Stat()
		if e != nil {
			_ = f.Close()
			return e
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != labUID || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Mode&07777 != 0600 || st.Nlink != 1 || st.Size > 1<<30 {
			_ = f.Close()
			return errors.New("ciphertext metadata invalid")
		}
		b, e := io.ReadAll(io.LimitReader(f, st.Size+1))
		ce := f.Close()
		if e != nil {
			return e
		}
		if ce != nil {
			return ce
		}
		after, e := os.Stat(path)
		if e != nil {
			return e
		}
		a, ok := after.Sys().(*syscall.Stat_t)
		if !ok || a.Dev != st.Dev || a.Ino != st.Ino || a.Uid != st.Uid || a.Mode != st.Mode || a.Nlink != st.Nlink || a.Size != st.Size || a.Mtim != st.Mtim || a.Ctim != st.Ctim {
			clear(b)
			return errors.New("ciphertext scan raced")
		}
		found := bytes.Contains(b, l.master) || bytes.Contains(b, l.payload)
		clear(b)
		if found {
			return errors.New("plaintext found in ciphertext store")
		}
		return nil
	})
}
func (l *deliveryLab) inspect() (map[string]string, error) {
	out, e := l.cli(labUID, []labAnswer{{"Application-store master secret: ", l.master}}, "appstore", "inspect", l.root)
	if e != nil {
		return nil, e
	}
	fields := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		p := strings.SplitN(line, "=", 2)
		if len(p) == 2 {
			fields[p[0]] = p[1]
		}
	}
	for _, k := range []string{"installation_sha256", "encoded_hash", "directory_dev", "directory_ino"} {
		if fields[k] == "" {
			return nil, errors.New("inspect metadata missing")
		}
	}
	if fields["installation_sha256"] != l.installationHash || fields["encoded_hash"] != l.encodedHash {
		return nil, errors.New("inspect differs from pinned ciphertext")
	}
	return fields, nil
}

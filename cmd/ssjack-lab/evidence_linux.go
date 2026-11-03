//go:build linux && amd64

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"syscall"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
)

func validReceipt(b []byte) bool {
	if len(b) != 96 {
		return false
	}
	a, c := b[:48], b[48:]
	nonceA, nonceB, bindingA, bindingB := a[:16], c[:16], a[16:], c[16:]
	return !bytes.Equal(nonceA, make([]byte, 16)) && !bytes.Equal(nonceB, make([]byte, 16)) &&
		!bytes.Equal(nonceA, nonceB) && !bytes.Equal(bindingA, make([]byte, 32)) && !bytes.Equal(bindingB, make([]byte, 32))
}
func ensureOwnerMode(path string, uid uint32, mode uint32) error {
	st, e := os.Stat(path)
	if e != nil {
		return e
	}
	raw, ok := st.Sys().(*syscall.Stat_t)
	if !ok || raw.Uid != uid || raw.Mode&07777 != mode {
		return errors.New("protected fixture metadata mismatch")
	}
	return nil
}
func digits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
func hashFile(path string) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	before, e := f.Stat()
	if e != nil {
		return "", e
	}
	st, ok := before.Sys().(*syscall.Stat_t)
	if !ok || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Uid != 0 || st.Mode&07777 != 0755 || st.Nlink != 1 || st.Size < 1 || st.Size > 16<<20 {
		return "", errors.New("fixture metadata invalid")
	}
	h := sha256.New()
	n, e := io.CopyN(h, f, st.Size)
	if e != nil || n != st.Size {
		return "", errors.New("bounded fixture read failed")
	}
	var extra [1]byte
	if extraN, extraErr := f.Read(extra[:]); extraN != 0 || extraErr != io.EOF {
		return "", errors.New("fixture length changed")
	}
	after, e := f.Stat()
	if e != nil {
		return "", e
	}
	current, ok := after.Sys().(*syscall.Stat_t)
	if !ok || current.Dev != st.Dev || current.Ino != st.Ino || current.Uid != st.Uid || current.Mode != st.Mode || current.Nlink != st.Nlink || current.Size != st.Size || current.Mtim != st.Mtim || current.Ctim != st.Ctim {
		return "", errors.New("fixture changed while hashing")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func (l *deliveryLab) register(fields map[string]string) error {
	driver, e := hashFile(declarativeauthority.DriverPath)
	if e != nil {
		return e
	}
	consumer, e := hashFile(declarativeauthority.ConsumerPath)
	if e != nil {
		return e
	}
	dev, ino := fields["directory_dev"], fields["directory_ino"]
	if !digits(dev) || !digits(ino) {
		return errors.New("store identity invalid")
	}
	expiry := time.Now().UTC().Add(2 * time.Hour).Format(time.RFC3339)
	answers := []labAnswer{{"Exact canonical confidential-delivery reference: ", []byte(l.ref)}, {"Repeat exact canonical reference: ", []byte(l.ref)}, {"Trusted absolute StorePath (human verified, never supplied by model tooling): ", []byte(l.root)}, {"Repeat exact StorePath: ", []byte(l.root)}, {"Verified store directory device number: ", []byte(dev)}, {"Repeat directory device number: ", []byte(dev)}, {"Verified store directory inode number: ", []byte(ino)}, {"Repeat directory inode number: ", []byte(ino)}, {"Independently verified encrypted InstallationSHA256: ", []byte(fields["installation_sha256"])}, {"Current snapshot EncodedHash from independently verified keeper CLI: ", []byte(fields["encoded_hash"])}, {"Independent driver SHA256: ", []byte(driver)}, {"Repeat driver SHA256: ", []byte(driver)}, {"Independent consumer SHA256: ", []byte(consumer)}, {"Repeat consumer SHA256: ", []byte(consumer)}, {"Type exact target identifier: ", []byte("target")}, {"Expiry RFC3339 UTC (within 24 hours): ", []byte(expiry)}, {"Keeper effective UID (non-root): ", []byte("65534")}, {"Repeat keeper UID: ", []byte("65534")}, {"Type REGISTER SYNTHETIC CONFIDENTIAL DELIVERY GRANT: ", []byte("REGISTER SYNTHETIC CONFIDENTIAL DELIVERY GRANT")}}
	_, e = l.cli(0, answers, "declarative", "register-delivery")
	return e
}
func (l *deliveryLab) revoke() error {
	answers := []labAnswer{{"Exact canonical confidential-delivery reference to revoke: ", []byte(l.ref)}, {"Repeat exact canonical reference: ", []byte(l.ref)}, {"Type REVOKE SYNTHETIC CONFIDENTIAL DELIVERY GRANT: ", []byte("REVOKE SYNTHETIC CONFIDENTIAL DELIVERY GRANT")}}
	_, e := l.cli(0, answers, "declarative", "revoke-delivery")
	return e
}

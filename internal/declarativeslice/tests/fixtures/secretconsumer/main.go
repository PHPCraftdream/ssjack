//go:build linux && amd64

package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"io"
	"os"
	"syscall"
	"time"
)

// behavior is varied only when producing separately pinned CI fixture binaries.
var behavior = "golden"

const receiptPath = "/var/lib/ssjack/synthetic/consumer-receipt"
const secret = "scoped secret"

func digest(s string) []byte { h := sha256.Sum256([]byte(s)); return h[:] }
func fail()                  { os.Exit(3) }

func main() {
	if len(os.Args) != 1 || len(os.Environ()) != 0 {
		fail()
	}
	var request [64]byte
	if _, err := io.ReadFull(os.Stdin, request[:]); err != nil || string(request[:8]) != "SSINK001" || binary.BigEndian.Uint64(request[56:]) != uint64(len(secret)) {
		fail()
	}
	var ready [160]byte
	copy(ready[:8], "SSRDY001")
	copy(ready[8:64], request[8:64])
	copy(ready[64:96], digest("target"))
	copy(ready[96:128], digest("synthetic-delivery-v1"))
	copy(ready[128:160], digest("synthetic-confidential-delivery"))
	if behavior == "wrong-ready" {
		ready[64] ^= 0xff
	}
	if _, err := os.Stdout.Write(ready[:]); err != nil {
		fail()
	}
	if behavior == "partial" {
		var one [1]byte
		_, _ = io.ReadFull(os.Stdin, one[:])
		fail()
	}
	want := []byte(secret)
	if behavior == "wrong-secret" {
		want = []byte("not scoped secret")
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(os.Stdin, got); err != nil {
		fail()
	}
	if subtle.ConstantTimeCompare(got, want) != 1 {
		fail()
	}
	clear(got)
	var extra [1]byte
	if n, err := os.Stdin.Read(extra[:]); n != 0 || err != io.EOF {
		fail()
	}
	if behavior == "lost" {
		record(request[8:24], request[24:56])
		fail()
	}
	if err := record(request[8:24], request[24:56]); err != nil {
		fail()
	}
	h := sha256.Sum256([]byte(secret))
	var ack [96]byte
	copy(ack[:8], "SSACK001")
	copy(ack[8:64], request[8:64])
	copy(ack[64:], h[:])
	if behavior == "wait" {
		deadline := time.Now().Add(5 * time.Second)
		for {
			if _, err := os.Stat("/var/lib/ssjack/synthetic/cancel-ack"); err == nil {
				if err := os.Remove("/var/lib/ssjack/synthetic/cancel-ack"); err != nil {
					fail()
				}
				break
			}
			if time.Now().After(deadline) {
				fail()
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	if _, err := os.Stdout.Write(ack[:]); err != nil {
		fail()
	}
	clear(ack[:])
}

// The fixed marker records a received effect, never payload-derived data.
func record(nonce, binding []byte) error {
	fd, err := syscall.Open("/var/lib/ssjack/synthetic", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	var st syscall.Stat_t
	if err = syscall.Fstat(fd, &st); err != nil || st.Mode&syscall.S_IFMT != syscall.S_IFDIR || st.Uid == 0 {
		return syscall.EPERM
	}
	f, err := syscall.Openat(fd, "consumer-receipt", syscall.O_WRONLY|syscall.O_APPEND|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer syscall.Close(f)
	if err = syscall.Fstat(f, &st); err != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Nlink != 1 || st.Mode&0777 != 0600 {
		return syscall.EPERM
	}
	// Bind each nonsecret receipt record to its delivery nonce and grant digest.
	var marker [48]byte
	copy(marker[:16], nonce)
	copy(marker[16:], binding)
	_, err = syscall.Write(f, marker[:])
	clear(marker[:])
	return err
}

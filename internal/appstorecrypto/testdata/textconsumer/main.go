package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
)

var expectedSHA256 string
var targetSHA256 string
var purposeSHA256 string
var revisionSHA256 string

func main() {
	if len(os.Environ()) != 0 {
		os.Exit(3)
	}
	expected, err := hex.DecodeString(expectedSHA256)
	if err != nil || len(expected) != sha256.Size {
		os.Exit(3)
	}
	var request [64]byte
	if _, err := io.ReadFull(os.Stdin, request[:]); err != nil || string(request[:8]) != "SSINK001" {
		os.Exit(3)
	}
	length := binary.BigEndian.Uint64(request[56:64])
	if length > 1<<40 {
		os.Exit(3)
	}
	var ready [160]byte
	copy(ready[:64], request[:])
	copy(ready[:8], "SSRDY001")
	if targetSHA256 == "" && revisionSHA256 == "" && purposeSHA256 == "" {
		ready[64], ready[96], ready[128] = 3, 4, 5
	} else {
		for _, binding := range []struct {
			value  string
			offset int
		}{{targetSHA256, 64}, {revisionSHA256, 96}, {purposeSHA256, 128}} {
			digest, err := hex.DecodeString(binding.value)
			if err != nil || len(digest) != sha256.Size {
				os.Exit(3)
			}
			copy(ready[binding.offset:binding.offset+sha256.Size], digest)
		}
	}
	if _, err := os.Stdout.Write(ready[:]); err != nil {
		os.Exit(3)
	}
	hash := sha256.New()
	var buffer [16384]byte
	defer clear(buffer[:])
	for offset := uint64(0); offset < length; {
		count := uint64(len(buffer))
		if count > length-offset {
			count = length - offset
		}
		if _, err := io.ReadFull(os.Stdin, buffer[:count]); err != nil {
			os.Exit(3)
		}
		_, _ = hash.Write(buffer[:count])
		offset += count
		clear(buffer[:])
	}
	var extra [1]byte
	if n, err := os.Stdin.Read(extra[:]); n != 0 || err != io.EOF {
		os.Exit(3)
	}
	if !equal(hash.Sum(nil), expected) {
		os.Exit(3)
	}
	var receipt [96]byte
	copy(receipt[:64], request[:])
	copy(receipt[:8], "SSACK001")
	copy(receipt[64:], expected)
	if _, err := os.Stdout.Write(receipt[:]); err != nil {
		os.Exit(3)
	}
	clear(receipt[:])
}

func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var different byte
	for i := range a {
		different |= a[i] ^ b[i]
	}
	return different == 0
}

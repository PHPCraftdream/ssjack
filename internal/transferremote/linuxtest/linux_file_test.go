//go:build linux

package linuxtest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"strconv"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	. "github.com/PHPCraftdream/ssjack/internal/transferremote"
	"github.com/PHPCraftdream/ssjack/internal/transferremote/core"
)

// linuxModeOf runs `stat -c %a` on path through the raw runner and returns
// the trimmed octal mode string.
func linuxModeOf(t *testing.T, run remote.StreamRunner, path string) string {
	t.Helper()
	var out bytes.Buffer
	ctx := context.Background()
	command := "stat -c %a " + core.ShellQuote(path)
	code, err := run(ctx, "t", command, nil, &out, io.Discard)
	if err != nil || code != 0 {
		t.Fatalf("stat -c %%a %s failed: code=%d err=%v", path, code, err)
	}
	return strings.TrimSpace(out.String())
}

// linuxUmaskOf returns the remote umask as reported by a plain `umask`.
func linuxUmaskOf(t *testing.T, run remote.StreamRunner) uint32 {
	t.Helper()
	var out bytes.Buffer
	code, err := run(context.Background(), "t", "umask", nil, &out, io.Discard)
	if err != nil || code != 0 {
		t.Fatalf("umask failed: code=%d err=%v", code, err)
	}
	mask, err := strconv.ParseUint(strings.TrimSpace(out.String()), 8, 32)
	if err != nil {
		t.Fatalf("parse umask %q: %v", out.String(), err)
	}
	return uint32(mask)
}

func TestFileRoundTripLinux(t *testing.T) {
	ctx := context.Background()
	run := linuxShRunner()
	r := New(run, "t", transfercore.DefaultLimits())
	dir := t.TempDir()

	pattern := make([]byte, 256*1024)
	for i := range pattern {
		pattern[i] = byte(i % 251)
	}
	pattern[0] = 0x00
	pattern[1] = 0xFF
	pattern[2] = '\n'
	pattern[3] = 0xFF
	pattern[4] = '\n'
	small := []byte("hello\n\x00\xffworld\n")

	cases := []struct {
		name string
		data []byte
	}{
		{"plain.bin", pattern},
		{"with space.bin", small},
		{"ünïcode-ñame.bin", small},
		{"quote'name.bin", small},
		{"big pattern.bin", pattern},
		{"executable.sh", small},
	}
	payloads := make(map[string][]byte, len(cases))
	for _, c := range cases {
		payloads[c.name] = c.data
		path := dir + "/" + c.name
		executable := c.name == "executable.sh"
		n, err := r.WriteFile(ctx, path, bytes.NewReader(c.data), executable)
		if err != nil {
			t.Fatalf("WriteFile(%s): %v", c.name, err)
		}
		if n != int64(len(c.data)) {
			t.Fatalf("WriteFile(%s) returned %d bytes, want %d", c.name, n, len(c.data))
		}
	}

	mask := linuxUmaskOf(t, run)
	wantPlain := strconv.FormatUint(uint64(0o666&^mask), 8)
	wantExec := strconv.FormatUint(uint64((0o666&^mask)|0o111), 8)
	maskText := strconv.FormatUint(uint64(mask), 8)

	for name, want := range payloads {
		path := dir + "/" + name
		size, hash, err := r.StatFile(ctx, path)
		if err != nil {
			t.Fatalf("StatFile(%s): %v", name, err)
		}
		if size != int64(len(want)) {
			t.Fatalf("StatFile(%s) size = %d, want %d", name, size, len(want))
		}
		local := sha256.Sum256(want)
		if hash != local {
			t.Fatalf("StatFile(%s) hash mismatch with local sha256", name)
		}

		var got bytes.Buffer
		n, err := r.ReadFile(ctx, path, &got)
		if err != nil {
			t.Fatalf("ReadFile(%s): %v", name, err)
		}
		if n != int64(len(want)) {
			t.Fatalf("ReadFile(%s) returned %d bytes, want %d", name, n, len(want))
		}
		if !bytes.Equal(got.Bytes(), want) {
			t.Fatalf("ReadFile(%s) content is not byte-identical to the payload", name)
		}

		wantMode := wantPlain
		if name == "executable.sh" {
			wantMode = wantExec
		}
		if mode := linuxModeOf(t, run, path); mode != wantMode {
			t.Fatalf("WriteFile(%s) produced mode %s, want %s (remote umask %s)", name, mode, wantMode, maskText)
		}
	}

	probe := func(path string) int {
		var out bytes.Buffer
		command := "[ -x " + core.ShellQuote(path) + " ]"
		code, err := run(context.Background(), "t", command, nil, &out, io.Discard)
		if err != nil {
			t.Fatalf("executable probe on %s failed: %v", path, err)
		}
		return code
	}
	if code := probe(dir + "/executable.sh"); code != 0 {
		t.Fatalf("[ -x ] on executable file exited %d, want 0", code)
	}
	if code := probe(dir + "/plain.bin"); code == 0 {
		t.Fatalf("[ -x ] on non-executable file exited 0, want nonzero")
	}
}

package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"unicode/utf8"

	"github.com/PHPCraftdream/ssjack/internal/appstoretextstream"
)

// backup implements the reverse subcommand: a reference-only copy of the
// approved source is published to --output exclusively. The output is staged
// beside its destination and linked into place, so an existing file is never
// replaced; that failure is discovered after dispatch and is unknown.
func backup(ctx context.Context, args []string) string {
	flags := flag.NewFlagSet("backup-text", flag.ContinueOnError)
	file := flags.String("file", "", "")
	output := flags.String("output", "", "")
	profile := flags.String("profile", "", "")
	references := flags.String("stream-references", "", "")
	set, ok := parse(flags, args)
	if !ok || *file == "" || *output == "" || *profile == "" || (set["stream-references"] && *references == "") {
		return statusWithheld
	}
	c, ok := connect(*profile)
	if !ok {
		return statusWithheld
	}
	defer c.client.CloseIdleConnections()
	staging, ok := stage(*output)
	if !ok {
		return statusWithheld
	}
	defer staging.discard()
	if set["stream-references"] {
		return backupStream(ctx, c, *profile, *file, *references, staging)
	}
	return backupText(ctx, c, *file, staging)
}

func backupText(ctx context.Context, c *connection, file string, staging *staged) string {
	id, ok := operationID()
	if !ok {
		return statusWithheld
	}
	result, ok := c.tool(ctx, "text_reverse_copy", map[string]string{
		"operation_id": id, "file": file, "mode": "reverse-copy-v1",
	}, copyReplyLimit)
	if !ok {
		return statusUnknown
	}
	if result.status != statusReceived {
		return refused(result.status)
	}
	if result.text == nil || len(*result.text) > copyLimit || !utf8.ValidString(*result.text) || bytes.IndexByte([]byte(*result.text), 0) >= 0 {
		return statusUnknown
	}
	if _, err := io.WriteString(staging.file, *result.text); err != nil || !staging.publish() {
		return statusUnknown
	}
	return statusReceived
}

// backupStream accepts a copy only after the terminal frame, complete body EOF,
// exact counters and a clean text check; everything else removes the staging.
func backupStream(ctx context.Context, c *connection, profile, file, referencesPath string, staging *staged) string {
	references, ok := readReferences(referencesPath)
	if !ok {
		return statusWithheld
	}
	id, ok := operationID()
	if !ok {
		return statusWithheld
	}
	line, ok := streamHeader{Format: streamFormat, OperationID: id, Profile: profile, File: file, References: references}.line()
	if !ok {
		return statusWithheld
	}
	request, err := c.request(ctx, reversePath, streamContentType, bytes.NewReader(line))
	if err != nil {
		return statusWithheld
	}
	response, err := c.client.Do(request)
	if err != nil {
		return statusUnknown
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusBadRequest || response.StatusCode == http.StatusForbidden {
		return statusWithheld
	}
	kind, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || response.StatusCode != http.StatusOK {
		return statusUnknown
	}
	switch kind {
	case streamContentType:
		guard := &textGuard{out: staging.file}
		if appstoretextstream.Decode(ctx, response.Body, guard, id, appstoretextstream.MaxBytes) != nil || !guard.complete() || !staging.publish() {
			return statusUnknown
		}
		return statusReceived
	case "application/json":
		reply, ok := readReply(response, id)
		if !ok {
			return statusUnknown
		}
		return refused(reply.Status)
	}
	return statusUnknown
}

// staged is a private same-directory file that becomes the output only by an
// exclusive hard link once the copy is complete.
type staged struct {
	file   *os.File
	output string
}

func stage(output string) (*staged, bool) {
	file, err := os.CreateTemp(filepath.Dir(output), "."+filepath.Base(output)+".*.tmp")
	if err != nil {
		return nil, false
	}
	return &staged{file: file, output: output}, true
}

func (s *staged) publish() bool {
	return s.file.Sync() == nil && s.file.Close() == nil && os.Link(s.file.Name(), s.output) == nil
}

func (s *staged) discard() {
	_ = s.file.Close()
	_ = os.Remove(s.file.Name())
}

var errText = errors.New("copy is not valid text")

// textGuard forwards UTF-8 text without NUL bytes and refuses anything else,
// holding back an incomplete trailing rune until the next write.
type textGuard struct {
	out  io.Writer
	tail []byte
}

func (g *textGuard) Write(p []byte) (int, error) {
	data := append(append([]byte(nil), g.tail...), p...)
	end := 0
	for end < len(data) {
		if data[end] == 0 {
			return 0, errText
		}
		if !utf8.FullRune(data[end:]) {
			break
		}
		r, size := utf8.DecodeRune(data[end:])
		if r == utf8.RuneError && size == 1 {
			return 0, errText
		}
		end += size
	}
	g.tail = append(g.tail[:0], data[end:]...)
	if _, err := g.out.Write(data[:end]); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (g *textGuard) complete() bool { return len(g.tail) == 0 }

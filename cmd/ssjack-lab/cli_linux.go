//go:build linux && amd64

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func (l *deliveryLab) cli(uid int, answers []labAnswer, args ...string) (string, error) {
	type encoded struct {
		Prompt string `json:"prompt"`
		Answer string `json:"answer"`
	}
	ea := make([]encoded, len(answers))
	for i, a := range answers {
		ea[i] = encoded{a.Prompt, base64.StdEncoding.EncodeToString(a.Answer)}
	}
	payload, e := json.Marshal(ea)
	if e != nil {
		return "", errors.New("PTY input failure")
	}
	defer clear(payload)
	parent := l.workspace
	if parent == "" {
		parent = "/tmp"
	}
	w, e := os.MkdirTemp(parent, "ssjack-lab-cli-")
	if e != nil {
		return "", errors.New("workspace failure")
	}
	defer os.RemoveAll(w)
	if e = os.Chown(w, uid, uid); e != nil {
		return "", errors.New("workspace failure")
	}
	if e = os.Chmod(w, 0700); e != nil {
		return "", errors.New("workspace failure")
	}
	argv := append([]string{ptyPath, cliPath}, args...)
	cmd := exec.Command("python3", argv...)
	cmd.Dir = w
	cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + w, "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "SSJACK_DELIVERY_UID=" + strconv.Itoa(uid)}
	cmd.Stdin = bytes.NewReader(payload)
	raw, e := cmd.Output()
	if e != nil {
		clear(raw)
		return "", errors.New("PTY command failed")
	}
	defer clear(raw)
	var r labResult
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&r) != nil || dec.Decode(new(any)) != io.EOF || r.PromptsAnswered < 0 || r.PromptsAnswered > len(answers) || len(r.Stdout) > 65536 {
		return "", errors.New("invalid PTY result")
	}
	for _, s := range [][]byte{l.master, l.payload, l.anchor.privateDER} {
		if len(s) > 0 && bytes.Contains(raw, s) {
			return "", errors.New("secret disclosure")
		}
		b64 := base64.StdEncoding.EncodeToString(s)
		if b64 != "" && strings.Contains(r.Stdout, b64) {
			return "", errors.New("secret disclosure")
		}
	}
	codes := map[string]string{"no active delivery grant": "no-active-grant", "no unique active delivery grant": "no-unique-active-grant", "application-store setup failed": "appstore-setup", "declarative authority unavailable or invalid": "authority"}
	if r.Refusal != "" {
		code, ok := codes[r.Refusal]
		if !ok || r.ExitCode == 0 || r.PromptsAnswered < 1 {
			return "", errors.New("untyped refusal")
		}
		return "", &labRefusal{code}
	}
	if r.ExitCode != 0 || r.PromptsAnswered != len(answers) {
		return "", errors.New("CLI failed")
	}
	return r.Stdout, nil
}

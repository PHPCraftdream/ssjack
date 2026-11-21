package delivery

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/testsupport/childdiag"
	"github.com/PHPCraftdream/ssjack/internal/flakediag"
)

type deliveryAnswer struct {
	Prompt string `json:"prompt"`
	Answer []byte `json:"answer"`
}

type deliveryProcessEvidence struct {
	WrapperPID  int
	WrapperExit int
	ChildPID    int
	ChildExit   int

	class         string
	cleanup       string
	prompts       int
	stdoutBytes   int
	terminalBytes int
	elapsedMS     int
}

func (e deliveryProcessEvidence) render() string {
	return fmt.Sprintf("delivery pty evidence: class=%s cleanup=%s wrapper_pid=%d wrapper_exit=%d child_pid=%d child_exit=%d prompts_answered=%d stdout_bytes=%d terminal_bytes=%d elapsed_ms=%d",
		e.class, e.cleanup, e.WrapperPID, e.WrapperExit, e.ChildPID, e.ChildExit, e.prompts, e.stdoutBytes, e.terminalBytes, e.elapsedMS)
}

const deliveryUnknownExit = -256

const deliveryResultLimit = 6*65536 + 1024

type deliveryPTYCapture struct{ buf bytes.Buffer }

func (b *deliveryPTYCapture) Write(p []byte) (int, error) {
	if n := min(len(p), deliveryResultLimit+1-b.buf.Len()); n > 0 {
		_, _ = b.buf.Write(p[:n])
	}
	return len(p), nil
}

func decodeDeliveryPTY(out []byte, fields map[string]any) string {
	dec := json.NewDecoder(bytes.NewReader(out))
	dec.UseNumber()
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return "envelope-decode"
	}
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return "envelope-decode"
		}
		name, ok := key.(string)
		if !ok || fields[name] == nil {
			return "envelope-shape"
		}
		value, err := dec.Token()
		if err != nil {
			return "envelope-decode"
		}
		switch dst := fields[name].(type) {
		case *int:
			n, ok := value.(json.Number)
			if !ok {
				return "envelope-shape"
			}
			v, err := strconv.Atoi(string(n))
			if err != nil || strconv.Itoa(v) != string(n) {
				return "envelope-range"
			}
			*dst = v
		case *string:
			s, ok := value.(string)
			if !ok {
				return "envelope-shape"
			}
			*dst = s
		}
		delete(fields, name)
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return "envelope-decode"
	}
	if len(fields) != 0 {
		return "envelope-shape"
	}
	if _, err := dec.Token(); err != io.EOF {
		return "envelope-trailing"
	}
	return ""
}

type deliveryCLIRefusal struct{ Class, Code string }

type deliveryCLI struct {
	cli        string
	ptySecrets [3]string
}

func (f *deliveryFixture) deliveryCLI() deliveryCLI {
	return deliveryCLI{
		cli:        f.cli,
		ptySecrets: [3]string{f.anchor.Master, f.anchor.Secret, base64.StdEncoding.EncodeToString(f.anchor.PrivateDER)},
	}
}

func (e *deliveryCLIRefusal) Error() string { return "delivery CLI authority refusal" }

func (f *deliveryFixture) tryDeliveryCLIAs(t *testing.T, uid int, answers []deliveryAnswer, args ...string) (string, error) {
	return f.tryDeliveryCLIAsWithText(t, uid, answers, nil, args...)
}

func (f *deliveryFixture) tryDeliveryCLIAsWithText(t *testing.T, uid int, answers []deliveryAnswer, text []byte, args ...string) (string, error) {
	t.Helper()
	var evidence deliveryProcessEvidence
	out, err := f.deliveryCLI().tryDeliveryCLIWithContext(context.Background(), uid, answers, text, func(snapshot deliveryProcessEvidence) {
		evidence = snapshot
	}, args...)
	flakediag.OnFailure(t, func() string {
		if evidence.WrapperPID > 0 && evidence.WrapperExit != 0 && evidence.WrapperExit != deliveryUnknownExit {
			wrapper := &exec.Cmd{Args: []string{"python3"}, Process: &os.Process{Pid: evidence.WrapperPID}}
			childdiag.ExecDiag(t, "delivery PTY helper", wrapper, nil, fmt.Errorf("exit status %d", evidence.WrapperExit))
		}
		return evidence.render()
	})
	return out, err
}

func (c deliveryCLI) tryDeliveryCLIWithContext(ctx context.Context, uid int, answers []deliveryAnswer, text []byte, observe func(deliveryProcessEvidence), args ...string) (string, error) {
	evidence := deliveryProcessEvidence{
		WrapperExit: deliveryUnknownExit, ChildExit: deliveryUnknownExit,
		class: "preflight", cleanup: "unknown",
		prompts: -1, stdoutBytes: -1, terminalBytes: -1, elapsedMS: -1,
	}
	if observe != nil {
		defer func() { observe(evidence) }()
	}
	payloadAnswers := make([]struct {
		Prompt string `json:"prompt"`
		Answer string `json:"answer"`
	}, len(answers))
	for i, a := range answers {
		payloadAnswers[i].Prompt = a.Prompt
		payloadAnswers[i].Answer = base64.StdEncoding.EncodeToString(append([]byte(nil), a.Answer...))
	}
	payload, err := json.Marshal(payloadAnswers)
	if err != nil {
		return "", errors.New("delivery prompt payload encoding failed")
	}
	defer clear(payload)
	helper, err := filepath.Abs(filepath.Join("..", "..", "..", "..", "..", "scripts", "ci", "delivery", "delivery_pty.py"))
	if err != nil {
		return "", errors.New("delivery helper path unavailable")
	}
	workspace, err := os.MkdirTemp("/tmp", "ssjack-delivery-project-")
	if err != nil {
		return "", errors.New("delivery workspace creation failed")
	}
	defer os.RemoveAll(workspace)
	if err := os.Chown(workspace, uid, uid); err != nil {
		return "", errors.New("delivery workspace ownership failed")
	}
	cmd := exec.CommandContext(ctx, "python3", append([]string{helper, c.cli}, args...)...)
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
	cmd.WaitDelay = 3 * time.Second
	var readFD *os.File
	var writeFD *os.File
	if text != nil {
		if len(text) > 4096 {
			return "", errors.New("text selection exceeds bounded fixture limit")
		}
		readFD, writeFD, err = os.Pipe()
		if err != nil {
			return "", errors.New("text selection pipe unavailable")
		}
		if _, err = writeFD.Write(text); err != nil {
			_ = readFD.Close()
			_ = writeFD.Close()
			return "", errors.New("text selection pipe write failed")
		}
		_ = writeFD.Close()
		defer readFD.Close()
	}
	cmd.Dir = workspace
	cmd.Env = append(os.Environ(), "SSJACK_DELIVERY_UID="+strconv.Itoa(uid))
	if text != nil {
		cmd.ExtraFiles = []*os.File{readFD}
		cmd.Env = append(cmd.Env, "SSJACK_DELIVERY_TEXT_FD=3")
	}
	cmd.Stdin = bytes.NewReader(payload)
	var capture deliveryPTYCapture
	cmd.Stdout = &capture
	err = cmd.Run()
	out := capture.buf.Bytes()
	defer clear(out)
	if cmd.Process != nil {
		evidence.WrapperPID = max(0, cmd.Process.Pid)
	}
	if cmd.ProcessState != nil {
		if code := cmd.ProcessState.ExitCode(); code >= 0 && code <= 255 {
			evidence.WrapperExit = code
		} else if status, ok := cmd.ProcessState.Sys().(interface {
			Signaled() bool
			Signal() syscall.Signal
		}); ok && status.Signaled() {
			if signal := status.Signal(); signal >= 1 && signal <= 127 {
				evidence.WrapperExit = -int(signal)
			}
		}
	}
	envelopeLimit := deliveryResultLimit
	if err != nil {
		evidence.class = "wrapper-exec"
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			return "", errors.New("delivery PTY infrastructure failure")
		}
		envelopeLimit = 1024
	}
	if len(out) > envelopeLimit {
		evidence.class = "envelope-size"
		return "", errors.New("invalid delivery PTY envelope")
	}
	var pid, code, answered int
	if err != nil {
		var failure, cleanup string
		var stdout, terminal, elapsed int
		evidence.class = decodeDeliveryPTY(out, map[string]any{
			"failure": &failure, "cleanup": &cleanup, "child_pid": &pid, "child_exit": &code,
			"prompts_answered": &answered, "stdout_bytes": &stdout, "terminal_bytes": &terminal, "elapsed_ms": &elapsed,
		})
		if evidence.class == "" {
			switch failure {
			case "input", "spawn", "timeout", "stdout-overflow", "stdout-decode", "io", "reap", "prompts", "child-exit", "refusal":
				if cleanup != "ok" && cleanup != "reap-failed" {
					evidence.class = "envelope-class"
				} else if (cleanup == "reap-failed" && (pid <= 0 || code != deliveryUnknownExit)) ||
					pid < 0 || pid > 1<<31-1 || (code != deliveryUnknownExit && (pid == 0 || code < -127 || code > 255)) ||
					answered < 0 || answered > len(answers) || stdout < 0 || stdout > 69632 ||
					terminal < 0 || terminal > 69632 || elapsed < 0 || elapsed > 600000 {
					evidence.class = "envelope-range"
				} else {
					evidence.class, evidence.cleanup = failure, cleanup
					evidence.ChildPID, evidence.ChildExit = pid, code
					evidence.prompts, evidence.stdoutBytes, evidence.terminalBytes, evidence.elapsedMS = answered, stdout, terminal, elapsed
				}
			default:
				evidence.class = "envelope-class"
			}
		}
		return "", errors.New("delivery PTY infrastructure failure")
	}
	var refusal, stdout string
	evidence.class = decodeDeliveryPTY(out, map[string]any{
		"exit_code": &code, "child_pid": &pid, "prompts_answered": &answered, "refusal": &refusal, "stdout": &stdout,
	})
	if evidence.class != "" {
		return "", errors.New("invalid delivery PTY result")
	}
	if pid <= 0 || pid > 1<<31-1 || code < 0 || code > 255 || answered < 0 || answered > len(answers) || len(stdout) > 65536 {
		evidence.class = "envelope-range"
		return "", errors.New("invalid delivery PTY result")
	}
	evidence.class = "disclosure"
	for _, secret := range c.ptySecrets[:2] {
		if secret != "" && (strings.Contains(stdout, secret) || bytes.Contains(out, []byte(secret))) {
			return "", errors.New("CLI disclosed secret")
		}
	}
	if encoded := c.ptySecrets[2]; encoded != "" && strings.Contains(stdout, encoded) {
		return "", errors.New("CLI disclosed private key")
	}
	evidence.ChildPID, evidence.ChildExit = pid, code
	evidence.prompts, evidence.stdoutBytes = answered, len(stdout)
	allowed := map[string]string{"no active delivery grant": "no-active-grant", "no unique active delivery grant": "no-unique-active-grant", "application-store setup failed": "application-store-setup", "invalid declarative slice request": "invalid-slice-request", "declarative authority unavailable or invalid": "authority-unavailable"}
	if refusal != "" {
		evidence.class = "refusal"
		if mapped, ok := allowed[refusal]; ok && code == 1 && answered >= 1 {
			return stdout, &deliveryCLIRefusal{Class: "authority", Code: mapped}
		}
		return "", errors.New("unclassified delivery CLI result")
	}
	if code != 0 {
		evidence.class = "child-exit"
		return "", errors.New("delivery CLI child failed")
	}
	if answered != len(answers) {
		evidence.class = "prompts"
		return "", errors.New("delivery CLI did not answer all prompts")
	}
	evidence.class = "success"
	return stdout, nil
}

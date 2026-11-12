package ownerrotationtest

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/ownerterminal"
)

// scanner is implemented by every capture kind, so one scan covers all of them.
type scanner interface {
	Join(context.Context) error
	Contains([]byte) bool
	Clear()
}

type rotationPTYCapture struct {
	mu       sync.Mutex
	data     []byte
	changed  chan struct{}
	done     chan struct{}
	overflow bool
}

var rotationANSI = regexp.MustCompile("\\x1b\\[[0-?]*[ -/]*[@-~]")
var rotationConsentPattern = regexp.MustCompile(`(?:ROTATE|VERIFY-ONLY|CANCEL-PREPARED|ARCHIVE) [^[:space:]]+ [^[:space:]]+ revision=[0-9]+ operation=[[:xdigit:]]{32}`)

func captureRotationPTY(output io.Reader) *rotationPTYCapture {
	c := &rotationPTYCapture{changed: make(chan struct{}, 1), done: make(chan struct{})}
	go func() {
		defer close(c.done)
		buffer := make([]byte, 4096)
		defer clear(buffer)
		for {
			n, err := output.Read(buffer)
			c.mu.Lock()
			if len(c.data)+n <= 128<<10 && !c.overflow {
				c.data = append(c.data, buffer[:n]...)
			} else {
				c.overflow = true
			}
			c.mu.Unlock()
			select {
			case c.changed <- struct{}{}:
			default:
			}
			if err != nil {
				return
			}
		}
	}()
	return c
}

func (c *rotationPTYCapture) text() (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return rotationANSI.ReplaceAllString(strings.ReplaceAll(string(c.data), "\r", ""), ""), c.overflow
}

// await returns the first non-empty find(text) as soon as the output has it.
func (c *rotationPTYCapture) await(ctx context.Context, find func(string) string) (string, error) {
	for {
		text, overflow := c.text()
		if overflow {
			return "", errors.New("rotation terminal capture overflow")
		}
		if found := find(text); found != "" {
			return found, nil
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-c.done:
			final, _ := c.text()
			if found := find(final); found != "" {
				return found, nil
			}
			return "", errors.New("rotation CLI ended before the expected output")
		case <-c.changed:
		}
	}
}

func (c *rotationPTYCapture) Wait(ctx context.Context, expected string) error {
	_, err := c.await(ctx, func(text string) string {
		if strings.Contains(text, expected) {
			return expected
		}
		return ""
	})
	return err
}

func (c *rotationPTYCapture) consent(ctx context.Context) (string, error) {
	return c.await(ctx, rotationConsentPattern.FindString)
}

func (c *rotationPTYCapture) Contains(value []byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Contains(c.data, value)
}

func (c *rotationPTYCapture) Join(ctx context.Context) error {
	select {
	case <-c.done:
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.overflow {
			return errors.New("rotation terminal capture overflow")
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *rotationPTYCapture) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.data)
	c.data = nil
}

func rotationTestEnvironment() []string {
	var environment []string
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if !strings.HasPrefix(key, "SSJACK_") && key != "TERM" && key != "NO_COLOR" {
			environment = append(environment, entry)
		}
	}
	return append(environment, "TERM=xterm-256color", "NO_COLOR=1")
}

func rotationLineEnding() byte {
	if runtime.GOOS == "windows" {
		return '\r'
	}
	return '\n'
}

func writeRotationPTY(t *testing.T, terminal *ownerterminal.Terminal, input []byte) {
	t.Helper()
	defer clear(input)
	if _, err := terminal.Input.Write(input); err != nil {
		t.Fatal("rotation fixture PTY input failed")
	}
}

func sendRotationConsent(t *testing.T, terminal *ownerterminal.Terminal, phrase string) {
	t.Helper()
	writeRotationPTY(t, terminal, append([]byte(phrase), rotationLineEnding()))
}

func waitRotationPTY(t *testing.T, ctx context.Context, terminal *ownerterminal.Terminal) {
	t.Helper()
	if err := terminal.Wait(ctx); err != nil {
		t.Fatal("actual rotate-key CLI process failed", err)
	}
}

func waitRotationCapture(t *testing.T, ctx context.Context, capture *rotationPTYCapture, expected string) {
	t.Helper()
	if err := capture.Wait(ctx, expected); err != nil {
		t.Fatal("actual rotate-key CLI output missing", expected)
	}
}

func closeRotationTerminal(terminal *ownerterminal.Terminal) {
	cleanup, stop := context.WithTimeout(context.Background(), time.Minute)
	defer stop()
	_ = terminal.Close(cleanup)
}

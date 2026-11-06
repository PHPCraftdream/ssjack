package ownerterminal

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"golang.org/x/term"
)

func TestNativeTerminalChild(t *testing.T) {
	if os.Getenv("SSJACK_NATIVE_TERMINAL_CHILD") != "1" {
		t.Skip("native terminal child only")
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
		t.Fatal("child did not receive real terminal handles")
	}
	state, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	defer term.Restore(int(os.Stdin.Fd()), state)
	fmt.Fprintln(os.Stdout, "NATIVE-TERMINAL-READY")
	private, err := term.ReadPassword(int(os.Stdin.Fd()))
	defer clear(private)
	if err != nil || !bytes.Equal(private, []byte("synthetic hidden terminal input")) {
		t.Fatal("hidden terminal input was not received")
	}
	fmt.Fprintln(os.Stdout, "NATIVE-TERMINAL-ACK")
}

type terminalCapture struct {
	mu       sync.Mutex
	data     []byte
	overflow bool
	changed  chan struct{}
	done     chan struct{}
}

func captureTerminal(output io.Reader) *terminalCapture {
	capture := &terminalCapture{changed: make(chan struct{}, 1), done: make(chan struct{})}
	go func() {
		defer close(capture.done)
		buffer := make([]byte, 4096)
		defer clear(buffer)
		for {
			n, err := output.Read(buffer)
			capture.mu.Lock()
			if len(capture.data)+n <= 64<<10 && !capture.overflow {
				capture.data = append(capture.data, buffer[:n]...)
			} else {
				capture.overflow = true
			}
			capture.mu.Unlock()
			select {
			case capture.changed <- struct{}{}:
			default:
			}
			if err != nil {
				return
			}
		}
	}()
	return capture
}

func (c *terminalCapture) wait(ctx context.Context, text string) error {
	for {
		c.mu.Lock()
		found, overflow := bytes.Contains(c.data, []byte(text)), c.overflow
		c.mu.Unlock()
		if overflow {
			return ErrTerminal
		}
		if found {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.done:
			c.mu.Lock()
			found, overflow := bytes.Contains(c.data, []byte(text)), c.overflow
			c.mu.Unlock()
			if found && !overflow {
				return nil
			}
			return ErrTerminal
		case <-c.changed:
		}
	}
}

func TestNativeTerminal(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skip("native owner terminal target platforms only")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bridge, err := filepath.Abs(filepath.Join("..", "..", "scripts", "ci", "owner_pty_bridge.py"))
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"hidden-input", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			terminal, err := Start(ctx, Command{Executable: executable, UnixBridge: bridge,
				Args: []string{"-test.run=^TestNativeTerminalChild$"}, Environment: append(os.Environ(), "SSJACK_NATIVE_TERMINAL_CHILD=1")})
			if err != nil {
				t.Fatal(err)
			}
			capture := captureTerminal(terminal.Output)
			defer func() {
				cleanup, stop := context.WithTimeout(context.Background(), time.Minute)
				defer stop()
				_ = terminal.Close(cleanup)
				select {
				case <-capture.done:
					capture.mu.Lock()
					clear(capture.data)
					capture.mu.Unlock()
				case <-cleanup.Done():
					t.Error("native terminal reader did not join")
				}
			}()
			if err := capture.wait(ctx, "NATIVE-TERMINAL-READY"); err != nil {
				t.Fatal("real terminal readiness failed:", err)
			}
			if mode == "cancel" {
				cancel()
				joined, stop := context.WithTimeout(context.Background(), time.Minute)
				defer stop()
				if err := terminal.Wait(joined); !errors.Is(err, ErrTerminal) {
					t.Fatal("cancelled terminal did not join its child with a failed exit")
				}
				return
			}
			ending := "\n"
			if runtime.GOOS == "windows" {
				ending = "\r"
			}
			input := []byte("synthetic hidden terminal input" + ending)
			_, err = terminal.Input.Write(input)
			clear(input)
			if err != nil || capture.wait(ctx, "NATIVE-TERMINAL-ACK") != nil || terminal.Wait(ctx) != nil {
				t.Fatal("native terminal hidden-input exchange failed")
			}
			<-capture.done
			capture.mu.Lock()
			exposed := bytes.Contains(capture.data, []byte("synthetic hidden terminal input")) || capture.overflow
			capture.mu.Unlock()
			if exposed {
				t.Fatal("terminal echoed hidden input or exceeded its diagnostic bound")
			}
		})
	}
}

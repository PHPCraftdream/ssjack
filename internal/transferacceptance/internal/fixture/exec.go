//go:build linux || darwin

package fixture

import (
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

func (s *ExecServer) serve(conn net.Conn, config *ssh.ServerConfig) {
	defer s.wg.Done()
	defer func() {
		s.mu.Lock()
		delete(s.conns, conn)
		close(s.connsChanged)
		s.connsChanged = make(chan struct{})
		s.mu.Unlock()
		_ = conn.Close()
	}()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	connection, channels, requests, err := ssh.NewServerConn(conn, config)
	if err != nil {
		class := errorClass(err)
		s.mu.Lock()
		s.eventLocked(fixtureEvent{kind: "handshake-failed/" + class, op: "other", direction: "none"})
		s.mu.Unlock()
		return
	}
	_ = conn.SetDeadline(time.Time{})
	defer connection.Close()
	go ssh.DiscardRequests(requests)
	for channel := range channels {
		if channel.ChannelType() != "session" {
			_ = channel.Reject(ssh.UnknownChannelType, "sessions only")
			continue
		}
		ch, incoming, err := channel.Accept()
		if err != nil {
			continue
		}
		for request := range incoming {
			var parsed struct{ Command string }
			if request.Type != "exec" || ssh.Unmarshal(request.Payload, &parsed) != nil {
				_ = request.Reply(false, nil)
				continue
			}
			diagnostic := s.recordExec(parsed.Command)
			err := request.Reply(true, nil)
			s.step(diagnostic, "exec-reply/"+errorClass(err))
			s.noteEntered(parsed.Command)
			s.runExec(conn, ch, parsed.Command, diagnostic)
			break
		}
		_ = ch.Close()
	}
}

// runExec executes the command with sh -c in the sandbox, byte-exactly.
func (s *ExecServer) runExec(conn net.Conn, ch ssh.Channel, command string, diagnostic *execDiagnostic) {
	kill, corrupt, gate := s.plan(command)
	if gate != nil {
		s.step(diagnostic, "hold-wait")
		select {
		case <-gate:
			s.step(diagnostic, "hold-released")
		case <-time.After(2 * time.Minute):
			s.step(diagnostic, "hold-timeout")
		}
	}
	var stdin io.Reader = &diagnosticReader{upstream: ch, observe: s.observeStream(&diagnostic.stdin)}
	var stdout io.Writer = &diagnosticWriter{downstream: ch, observe: s.observeStream(&diagnostic.stdout)}
	stderr := &diagnosticWriter{downstream: ch.Stderr(), observe: s.observeStream(&diagnostic.stderr)}
	if corrupt.armed {
		stdin = &corruptingReader{reader: stdin, at: corrupt.amount, onFire: s.faultCallback(diagnostic, "corrupt-fired", "stdin", corrupt.amount)}
	}
	if kill.armed {
		stdin = &killingStream{reader: stdin, conn: conn, limit: kill.amount, onFire: s.faultCallback(diagnostic, "kill-fired", "stdin", kill.amount)}
		stdout = &killingStream{writer: stdout, conn: conn, limit: kill.amount, onFire: s.faultCallback(diagnostic, "kill-fired", "stdout", kill.amount)}
	}
	// SSJACK_REMOTE_SHELL overrides the fixture shell for the userland harness.
	shell := "sh"
	for _, entry := range s.env {
		if value, ok := strings.CutPrefix(entry, "SSJACK_REMOTE_SHELL="); ok {
			shell = value
			break
		}
	}
	cmd := exec.Command(shell, "-c", command)
	cmd.Dir = s.sandbox
	if s.env != nil {
		cmd.Env = s.env
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	status := s.runCommand(cmd, diagnostic)
	s.step(diagnostic, "exit-status-send-attempted")
	_, err := ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(status)}))
	s.step(diagnostic, "exit-status-send/"+errorClass(err))
	_ = ch.Close()
	s.mu.Lock()
	s.activeExecs--
	s.mu.Unlock()
}

// commandPump owns both pipe ends until Start returns. After a successful
// Start, only the copy goroutine owns the parent end.
type commandPump struct {
	child, parent *os.File
	copy          func() error
}

func startCommandPumps(cmd *exec.Cmd) (pumps []commandPump, err error) {
	defer func() {
		for _, pump := range pumps {
			_ = pump.child.Close()
			if err != nil {
				_ = pump.parent.Close()
			}
		}
	}()

	if src := cmd.Stdin; src != nil {
		if _, direct := src.(*os.File); !direct {
			r, w, err := os.Pipe()
			if err != nil {
				return pumps, err
			}
			cmd.Stdin = r
			pumps = append(pumps, commandPump{child: r, parent: w, copy: func() error {
				_, err := io.Copy(w, src)
				if pe, ok := err.(*os.PathError); ok && pe.Op == "write" && pe.Path == w.Name() && pe.Err == syscall.EPIPE {
					err = nil
				}
				if closeErr := w.Close(); err == nil {
					err = closeErr
				}
				return err
			}})
		}
	}
	for _, output := range [...]*io.Writer{&cmd.Stdout, &cmd.Stderr} {
		dst := *output
		if _, direct := dst.(*os.File); dst == nil || direct {
			continue
		}
		r, w, err := os.Pipe()
		if err != nil {
			return pumps, err
		}
		*output = w
		pumps = append(pumps, commandPump{child: w, parent: r, copy: func() error {
			_, err := io.Copy(dst, r)
			_ = r.Close()
			return err
		}})
	}
	return pumps, cmd.Start()
}

func (s *ExecServer) runCommand(cmd *exec.Cmd, diagnostic *execDiagnostic) int {
	// The legacy fallback is only an SSH wire status, not a process exit.
	const wireFallback = 111
	s.step(diagnostic, "start-attempted")
	pumps, err := startCommandPumps(cmd)
	if err != nil {
		s.step(diagnostic, "start-failed/"+errorClass(err))
		return wireFallback
	}
	s.mu.Lock()
	diagnostic.pid = cmd.Process.Pid
	diagnostic.process = processDiagnostic{kind: "running"}
	diagnostic.ioState = "pending"
	s.stepLocked(diagnostic, "started")
	s.mu.Unlock()

	// Buffer all results so pumps can finish even before Wait returns.
	results := make(chan error, len(pumps))
	for _, pump := range pumps {
		go func() { results <- pump.copy() }()
	}

	// Only files or nil reach exec.Cmd, so Wait does not join our pumps.
	err = cmd.Wait()
	result := processResult(cmd.ProcessState)
	class := errorClass(err)
	s.mu.Lock()
	diagnostic.process = result
	s.stepLocked(diagnostic, "process-wait-completed/"+class)
	s.mu.Unlock()

	var ioErr error
	for range pumps {
		if copyErr := <-results; ioErr == nil {
			ioErr = copyErr
		}
	}
	class = errorClass(ioErr)
	s.mu.Lock()
	diagnostic.ioState = "joined"
	s.stepLocked(diagnostic, "io-join-completed/"+class)
	s.mu.Unlock()

	if err == nil {
		if ioErr != nil {
			return wireFallback
		}
		return 0
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode()
	}
	return wireFallback
}

func (s *ExecServer) plan(command string) (injection, injection, chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kill, corrupt := s.kill, s.corrupt
	if !kill.armed || !strings.Contains(command, kill.match) {
		kill = injection{}
	}
	if !corrupt.armed || !strings.Contains(command, corrupt.match) {
		corrupt = injection{}
	}
	var gate chan struct{}
	for match, hold := range s.holds {
		if strings.Contains(command, match) {
			gate = hold
			break
		}
	}
	return kill, corrupt, gate
}

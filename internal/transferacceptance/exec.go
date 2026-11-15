//go:build linux

package transferacceptance

import (
	"errors"
	"io"
	"net"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

func (s *ExecServer) serve(conn net.Conn, config *ssh.ServerConfig) {
	defer s.wg.Done()
	defer func() {
		s.mu.Lock()
		delete(s.conns, conn)
		s.mu.Unlock()
		_ = conn.Close()
	}()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	connection, channels, requests, err := ssh.NewServerConn(conn, config)
	if err != nil {
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
			_ = request.Reply(true, nil)
			s.runExec(conn, ch, parsed.Command)
			break
		}
		_ = ch.Close()
	}
}

// runExec executes the command with sh -c in the sandbox, byte-exactly.
func (s *ExecServer) runExec(conn net.Conn, ch ssh.Channel, command string) {
	s.note(command)
	kill, corrupt, gate := s.plan(command)
	if gate != nil {
		select {
		case <-gate:
		case <-time.After(2 * time.Minute):
		}
	}
	var stdin io.Reader = ch
	var stdout io.Writer = ch
	if corrupt.armed {
		stdin = &corruptingReader{reader: ch, at: corrupt.amount}
	}
	if kill.armed {
		stdin = &killingStream{reader: stdin, conn: conn, limit: kill.amount}
		stdout = &killingStream{writer: stdout, conn: conn, limit: kill.amount}
	}
	cmd := exec.Command("sh", "-c", command)
	cmd.Dir = s.sandbox
	if s.env != nil {
		cmd.Env = s.env
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, ch.Stderr()
	err := cmd.Run()
	status := uint32(0)
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			status = uint32(exit.ExitCode())
		} else {
			status = 111
		}
	}
	_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
	_ = ch.Close()
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

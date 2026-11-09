package ownerpacket

import (
	"sync"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/keyfile"
)

// Server borrows an authenticated database context; it never exposes that key.
type Server struct {
	mu      sync.Mutex
	peer    peer
	hello   bool
	waiting uint64
}

func NewServer(key *keyfile.Unlocked, binding, savedCipher [32]byte) (*Server, error) {
	if key == nil || binding == ([32]byte{}) || savedCipher == ([32]byte{}) {
		return nil, ErrAuthentication
	}
	session, err := nonce()
	if err != nil {
		return nil, err
	}
	return &Server{peer: peer{key: key, binding: binding, session: session, digest: savedCipher, expires: time.Now().Add(Lease), sequence: 1, now: time.Now}}, nil
}

func (s *Server) Close()              { s.mu.Lock(); defer s.mu.Unlock(); s.peer.closed, s.peer.key = true, nil }
func (s *Server) Deadline() time.Time { s.mu.Lock(); defer s.mu.Unlock(); return s.peer.expires }

func (s *Server) Hello() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.hello || s.peer.live() != nil {
		return nil, s.peer.fail()
	}
	encoded, err := seal(s.peer.key, s.peer.packet("hello", "server", 0))
	if err != nil {
		s.peer.closed = true
		return nil, err
	}
	s.hello = true
	return encoded, nil
}

func (s *Server) Authenticate(encoded []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.hello || s.peer.ready || s.peer.live() != nil {
		return nil, s.peer.fail()
	}
	packet, err := open(s.peer.key, encoded)
	defer packet.clear()
	if err != nil || packet.Client == ([32]byte{}) || packet.Command != nil || packet.Reply != nil {
		return nil, s.peer.fail()
	}
	s.peer.client = packet.Client
	if !s.peer.matches(packet, "auth", "client", 0) {
		return nil, s.peer.fail()
	}
	acknowledgement, err := seal(s.peer.key, s.peer.packet("ready", "server", 0))
	if err != nil {
		s.peer.closed = true
		return nil, err
	}
	s.peer.ready = true
	return acknowledgement, nil
}

// OpenCommand admits exactly one authenticated command until Reply is issued.
// The caller owns the returned buffers and must Clear them after dispatch.
func (s *Server) OpenCommand(encoded []byte) (*Command, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.peer.ready || s.waiting != 0 || s.peer.live() != nil || s.peer.sequence > MaxMessages {
		return nil, s.peer.fail()
	}
	packet, err := open(s.peer.key, encoded)
	if err != nil {
		return nil, s.peer.fail()
	}
	if !s.peer.matches(packet, "command", "client", s.peer.sequence) || packet.Command == nil || packet.Reply != nil || !packet.Command.valid() {
		packet.clear()
		return nil, s.peer.fail()
	}
	s.waiting = s.peer.sequence
	s.peer.sequence++
	return packet.Command, nil
}

func (s *Server) Reply(reply Reply) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.peer.ready || s.waiting == 0 || s.peer.live() != nil || !reply.valid() {
		return nil, s.peer.fail()
	}
	packet := s.peer.packet("reply", "server", s.waiting)
	packet.Reply = &reply
	encoded, err := seal(s.peer.key, packet)
	if err != nil {
		s.peer.closed = true
		return nil, err
	}
	s.waiting = 0
	return encoded, nil
}

// Package ownerservice serves the retained private owner coordinator, never MCP.
package ownerservice

import (
	"context"
	"errors"
	"sync"

	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/ownerdispatch"
	"github.com/PHPCraftdream/ssjack/internal/ownerlocal"
	"github.com/PHPCraftdream/ssjack/internal/ownerpacket"
)

const maxPeers = 16

var ErrService = errors.New("owner service is unavailable or did not stop safely")

type coordinator interface {
	AcceptOwner(context.Context) (ownerlocal.Connection, error)
	OwnerPeer([32]byte) (*ownerpacket.Server, error)
}

type peerConnection struct{ connection ownerlocal.Connection }

type Service struct {
	manager    coordinator
	dispatcher *ownerdispatch.Dispatcher
	binding    [32]byte
	ctx        context.Context
	cancel     context.CancelFunc
	done       chan struct{}
	slots      chan struct{}
	mu         sync.Mutex
	peers      map[*peerConnection]struct{}
	fatal      bool
}

// Start borrows the Manager and its writer claim, without another unlock/listener.
// Close must complete before the caller closes the Manager or its key context.
func Start(ctx context.Context, manager *ownerdb.Manager) (*Service, error) {
	if ctx == nil || ctx.Err() != nil || manager == nil {
		return nil, ErrService
	}
	binding, err := manager.OwnerBinding()
	if err != nil {
		return nil, ErrService
	}
	probe, err := manager.OwnerPeer(binding)
	if err != nil {
		return nil, ErrService
	}
	probe.Close()
	dispatcher, err := ownerdispatch.New(manager)
	if err != nil {
		return nil, ErrService
	}
	lifetime, cancel := context.WithCancel(ctx)
	s := &Service{manager: manager, dispatcher: dispatcher, binding: binding,
		ctx: lifetime, cancel: cancel, done: make(chan struct{}), slots: make(chan struct{}, maxPeers),
		peers: make(map[*peerConnection]struct{})}
	go s.run()
	return s, nil
}

func (s *Service) Done() <-chan struct{} { return s.done }

func (s *Service) Close(ctx context.Context) error {
	if ctx == nil {
		return ErrService
	}
	s.cancel()
	select {
	case <-s.done:
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.fatal {
			return ErrService
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Service) closeConnections() {
	s.mu.Lock()
	connections := make([]ownerlocal.Connection, 0, len(s.peers))
	for peer := range s.peers {
		connections = append(connections, peer.connection)
	}
	s.mu.Unlock()
	for _, connection := range connections {
		connection.Close()
	}
}

package ownerservice

import (
	"context"
	"sync"

	"github.com/PHPCraftdream/ssjack/internal/ownerrpc"
)

func (s *Service) run() {
	var peers sync.WaitGroup
	defer func() {
		s.cancel()
		s.closeConnections()
		peers.Wait()
		close(s.done)
	}()
	for {
		select {
		case s.slots <- struct{}{}:
		case <-s.ctx.Done():
			return
		}
		connection, err := s.manager.AcceptOwner(s.ctx)
		if err != nil || connection == nil {
			if connection != nil {
				connection.Close()
			}
			<-s.slots
			if s.ctx.Err() == nil {
				s.mu.Lock()
				s.fatal = true
				s.mu.Unlock()
			}
			return
		}
		peer := &peerConnection{connection: connection}
		s.mu.Lock()
		if s.ctx.Err() != nil {
			s.mu.Unlock()
			connection.Close()
			<-s.slots
			return
		}
		s.peers[peer] = struct{}{}
		s.mu.Unlock()
		peers.Add(1)
		go func() {
			defer peers.Done()
			defer func() {
				peer.connection.Close()
				s.mu.Lock()
				delete(s.peers, peer)
				s.mu.Unlock()
				<-s.slots
			}()
			s.serve(peer)
		}()
	}
}

func (s *Service) serve(connection *peerConnection) {
	packet, err := s.manager.OwnerPeer(s.binding)
	if err != nil {
		return
	}
	defer packet.Close()
	lease, err := s.dispatcher.NewPeer(packet.Deadline())
	if err != nil {
		return
	}
	ctx, cancel := context.WithDeadline(s.ctx, packet.Deadline())
	defer cancel()
	// Authentication/protocol/receipt loss closes this peer, never replays it.
	// Manager state, not a disconnected client's receipt, determines final save.
	_ = ownerrpc.ServePeer(ctx, connection.connection, packet, lease)
}

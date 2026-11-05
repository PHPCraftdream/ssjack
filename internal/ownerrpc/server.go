package ownerrpc

import (
	"context"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/ownerlocal"
	"github.com/PHPCraftdream/ssjack/internal/ownerpacket"
)

// Handler receives only a validated closed command after mutual authentication.
// Dispatch must honor ctx and copy any private input retained after its return.
// Peer lease/import ownership is the handler's responsibility.
type Handler interface {
	Dispatch(context.Context, *ownerpacket.Command) ownerpacket.Reply
}

type serverPeer interface {
	Hello() ([]byte, error)
	Authenticate([]byte) ([]byte, error)
	OpenCommand([]byte) (*ownerpacket.Command, error)
	Reply(ownerpacket.Reply) ([]byte, error)
	Deadline() time.Time
	Close()
}

// ServePeer consumes the connection and packet peer, never the parent unlock.
// The caller must join it before closing the borrowed database context.
func ServePeer(ctx context.Context, connection ownerlocal.Connection, peer *ownerpacket.Server, handler Handler) error {
	if connection == nil || peer == nil || handler == nil {
		if connection != nil {
			connection.Close()
		}
		if peer != nil {
			peer.Close()
		}
		return ownerpacket.ErrProtocol
	}
	return servePeer(ctx, connection, peer, handler)
}

func servePeer(ctx context.Context, connection ownerlocal.Connection, peer serverPeer, handler Handler) error {
	defer peer.Close()
	defer connection.Close()
	if ctx == nil || ctx.Err() != nil {
		return ownerpacket.ErrProtocol
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return ownerpacket.ErrProtocol
	}
	lifetime, cancel := context.WithDeadline(ctx, peer.Deadline())
	defer cancel()
	handshake, stop, err := exchangeContext(lifetime, time.Now().Add(10*time.Second))
	if err != nil {
		return err
	}
	err = authenticateServer(handshake, connection, peer)
	stop()
	if err != nil {
		return err
	}
	for {
		encoded, err := ownerpacket.ReadFrame(lifetime, connection)
		if err != nil {
			return err
		}
		command, err := peer.OpenCommand(encoded)
		clear(encoded)
		if err != nil {
			return err
		}
		if command == nil {
			return ownerpacket.ErrProtocol
		}
		err = dispatchReply(lifetime, connection, peer, handler, command)
		if err != nil {
			return err
		}
	}
}

func authenticateServer(ctx context.Context, connection ownerlocal.Connection, peer serverPeer) error {
	hello, err := peer.Hello()
	if err != nil {
		return err
	}
	defer clear(hello)
	if err := ownerpacket.WriteFrame(ctx, connection, hello); err != nil {
		return err
	}
	authentication, err := ownerpacket.ReadFrame(ctx, connection)
	if err != nil {
		return err
	}
	defer clear(authentication)
	ready, err := peer.Authenticate(authentication)
	if err != nil {
		return err
	}
	defer clear(ready)
	return ownerpacket.WriteFrame(ctx, connection, ready)
}

func dispatchReply(ctx context.Context, connection ownerlocal.Connection, peer serverPeer, handler Handler, command *ownerpacket.Command) error {
	defer command.Clear()
	bounded, cancel, err := exchangeContext(ctx, peer.Deadline())
	if err != nil {
		return err
	}
	defer cancel()
	if err := bounded.Err(); err != nil {
		return err
	}
	reply := handler.Dispatch(bounded, command)
	encoded, err := peer.Reply(reply)
	if err != nil {
		return err
	}
	defer clear(encoded)
	return ownerpacket.WriteFrame(bounded, connection, encoded)
}

package ownerservice

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/ownerlocal"
	"github.com/PHPCraftdream/ssjack/internal/ownerpacket"
)

type coordinatorProbe struct {
	accept func(context.Context) (ownerlocal.Connection, error)
}

func (p *coordinatorProbe) AcceptOwner(ctx context.Context) (ownerlocal.Connection, error) {
	return p.accept(ctx)
}
func (p *coordinatorProbe) OwnerPeer([32]byte) (*ownerpacket.Server, error) { return nil, ErrService }

func probeService(ctx context.Context, manager coordinator) *Service {
	lifetime, cancel := context.WithCancel(ctx)
	s := &Service{manager: manager, ctx: lifetime, cancel: cancel, done: make(chan struct{}), slots: make(chan struct{}, maxPeers), peers: make(map[*peerConnection]struct{})}
	go s.run()
	return s
}

func TestServiceCloseCancelsAndJoinsAcceptWithoutClosingParent(t *testing.T) {
	entered := make(chan struct{})
	manager := &coordinatorProbe{accept: func(ctx context.Context) (ownerlocal.Connection, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	s := probeService(context.Background(), manager)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	defer s.Close(ctx)
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("service did not enter controlled accept")
	}
	if cap(s.slots) != 16 {
		t.Fatal("service admission is not bounded to sixteen slots")
	}
	if err := s.Close(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.Done():
	default:
		t.Fatal("close returned before accept joined")
	}
	if len(s.slots) != 0 {
		t.Fatal("service retained a reserved admission slot")
	}
}

func TestUnexpectedAcceptFailureNeverReportsSuccessfulService(t *testing.T) {
	for _, partial := range []bool{false, true} {
		connection := &connectionProbe{closed: make(chan struct{})}
		manager := &coordinatorProbe{accept: func(context.Context) (ownerlocal.Connection, error) {
			if partial {
				return connection, errors.New("synthetic-private-accept-diagnostic")
			}
			return nil, nil
		}}
		s := probeService(context.Background(), manager)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		select {
		case <-s.Done():
		case <-ctx.Done():
			t.Fatal("failed accept did not stop")
		}
		if err := s.Close(ctx); !errors.Is(err, ErrService) {
			t.Fatal("fatal accept was hidden or exposed raw diagnostics")
		}
		if partial {
			select {
			case <-connection.closed:
			default:
				t.Fatal("partial accepted connection leaked")
			}
		}
		cancel()
	}
}

type connectionProbe struct {
	once   sync.Once
	closed chan struct{}
}

func (c *connectionProbe) Read(context.Context, []byte) (int, error)  { return 0, io.ErrClosedPipe }
func (c *connectionProbe) Write(context.Context, []byte) (int, error) { return 0, io.ErrClosedPipe }
func (c *connectionProbe) Close() error                               { c.once.Do(func() { close(c.closed) }); return nil }

func TestUnavailablePeerFactoryClosesOnlyThatPeer(t *testing.T) {
	connection := &connectionProbe{closed: make(chan struct{})}
	first := true
	manager := &coordinatorProbe{accept: func(ctx context.Context) (ownerlocal.Connection, error) {
		if first {
			first = false
			return connection, nil
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	s := probeService(context.Background(), manager)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	defer s.Close(ctx)
	select {
	case <-connection.closed:
	case <-ctx.Done():
		t.Fatal("failed factory leaked its owned connection")
	}
	if err := s.Close(ctx); err != nil {
		t.Fatal("unavailable peer incorrectly stopped the whole service")
	}
	if len(s.peers) != 0 || len(s.slots) != 0 {
		t.Fatal("joined service retained peer state")
	}
}

func TestCloseDeadlineDoesNotPretendPeersJoined(t *testing.T) {
	lifetime, cancel := context.WithCancel(context.Background())
	s := &Service{ctx: lifetime, cancel: cancel, done: make(chan struct{})}
	ctx, stop := context.WithCancel(context.Background())
	stop()
	if err := s.Close(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("unfinished shutdown reported success")
	}
	select {
	case <-s.Done():
		t.Fatal("deadline closed the joined receipt")
	default:
	}
	close(s.done)
	if err := s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

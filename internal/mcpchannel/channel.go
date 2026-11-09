package mcpchannel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

const (
	MaxChannels         = 16
	MaxRequestBytes     = 64 << 10
	MaxInventoryBytes   = 192 << 10
	MaxResultBytes      = 64 << 10
	MaxClientInputBytes = 48 << 10
	MaxToolBytes        = 64
	MaxRuntimeMessages  = 4096
	OperationBudget     = 20 * time.Second
	RuntimeLease        = 10 * time.Minute
)

var (
	ErrSetup   = errors.New("remote MCP channel setup failed")
	ErrCleanup = errors.New("remote MCP channel cleanup did not complete")
)

type Handler interface {
	Describe(context.Context) ([]byte, error)
	Call(context.Context, string, []byte) ([]byte, error)
}

type HandlerForOrdinal func(int) Handler

type channelServer struct {
	server  *broker.Server
	handler Handler
}

type ChannelSet struct {
	mu            sync.Mutex
	servers       []*channelServer
	descriptors   []Descriptor
	guard         *outputguard.Snapshot
	cancel        context.CancelFunc
	done          chan struct{}
	setupDone     chan struct{}
	joined        int
	finished      bool
	cleanupFailed bool
	handlers      []Handler
}

func Open(ctx context.Context, count int, ttl time.Duration, handlerForOrdinal HandlerForOrdinal) (*ChannelSet, error) {
	if ctx == nil || ctx.Err() != nil || count < 1 || count > MaxChannels || ttl <= 0 || ttl > RuntimeLease || handlerForOrdinal == nil {
		return nil, ErrSetup
	}
	deadline := time.Now().Add(RuntimeLease)
	if parentDeadline, ok := ctx.Deadline(); ok && parentDeadline.Before(deadline) {
		deadline = parentDeadline
	}
	if !deadline.After(time.Now()) {
		return nil, ErrSetup
	}
	ownerCtx, cancel := context.WithDeadline(ctx, deadline)
	handlers := make([]Handler, count)
	set := &ChannelSet{cancel: cancel, done: make(chan struct{}), setupDone: make(chan struct{}), handlers: handlers}
	for ordinal := range handlers {
		handlers[ordinal] = handlerForOrdinal(ordinal)
		if handlers[ordinal] == nil {
			cleanupErr := closeHandlers(handlers[:ordinal])
			cancel()
			if cleanupErr != nil {
				set.cleanupFailed = true
				set.finishSetup()
				return set, ErrCleanup
			}
			return nil, ErrSetup
		}
	}
	sessions, tokens, pins, endpoints := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for ordinal, handler := range handlers {
		if ownerCtx.Err() != nil {
			return set.fail()
		}
		session, err := wire.RandomToken()
		if err != nil || sessions[session] || tokens[session] || pins[session] {
			return set.fail()
		}
		token, err := wire.RandomToken()
		if err != nil || session == token || tokens[token] || sessions[token] || pins[token] {
			return set.fail()
		}
		sessions[session], tokens[token] = true, true
		bootstrapTTL := min(ttl, time.Until(deadline))
		if bootstrapTTL <= 0 {
			return set.fail()
		}
		started := time.Now()
		server, err := broker.Listen(ownerCtx, session, token, bootstrapTTL, channelHandler(handler))
		if err != nil {
			return set.fail()
		}
		channel := &channelServer{server: server, handler: handler}
		set.mu.Lock()
		set.servers = append(set.servers, channel)
		set.mu.Unlock()
		go set.supervise(ownerCtx, channel)
		expires := started.Add(bootstrapTTL)
		if deadline.Before(expires) {
			expires = deadline
		}
		if ttlDeadline := started.Add(ttl); ttlDeadline.Before(expires) {
			expires = ttlDeadline
		}
		expiresUnix := expires.Unix()
		if expires.Nanosecond() != 0 {
			expiresUnix++
		}
		d := Descriptor{Version: VersionRemoteMCP, Ordinal: ordinal, Session: session, Endpoint: server.Endpoint(), Pin: server.Pin(), Token: token, ExpiresUnix: expiresUnix}
		if pins[d.Pin] || endpoints[d.Endpoint] || sessions[d.Pin] || tokens[d.Pin] || d.Pin == d.Session || d.Pin == d.Token || !d.valid(time.Now()) {
			return set.fail()
		}
		pins[d.Pin], endpoints[d.Endpoint] = true, true
		sessions[d.Session], tokens[d.Token] = true, true
		set.mu.Lock()
		set.descriptors = append(set.descriptors, d)
		set.mu.Unlock()
	}
	set.mu.Lock()
	patterns := make([][]byte, len(set.descriptors))
	for i := range set.descriptors {
		patterns[i] = []byte(set.descriptors[i].Token)
	}
	set.mu.Unlock()
	guard, err := outputguard.New(patterns)
	for i := range patterns {
		clear(patterns[i])
	}
	if err != nil || guard == nil {
		return set.fail()
	}
	set.guard = guard
	set.finishSetup()
	return set, nil
}

func (s *ChannelSet) fail() (*ChannelSet, error) {
	s.cancel()
	s.mu.Lock()
	count := len(s.servers)
	remaining := s.handlers[count:]
	s.mu.Unlock()
	if closeHandlers(remaining) != nil {
		s.mu.Lock()
		s.cleanupFailed = true
		s.mu.Unlock()
	}
	s.finishSetup()
	if count == 0 {
		if s.closeResult() != nil {
			return s, ErrCleanup
		}
		return nil, ErrSetup
	}
	select {
	case <-s.done:
		if s.closeResult() != nil {
			return s, ErrCleanup
		}
		return nil, ErrSetup
	default:
		return s, ErrCleanup
	}
}

func (s *ChannelSet) finishSetup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.setupDone:
	default:
		close(s.setupDone)
	}
	s.finishLocked()
}

func (s *ChannelSet) supervise(ctx context.Context, channel *channelServer) {
	select {
	case <-ctx.Done():
	case <-channel.server.Done():
	}
	cleanupErr := closeLifecycle(channel.handler)
	channel.server.Close()
	s.mu.Lock()
	if cleanupErr != nil {
		s.cleanupFailed = true
	}
	s.joined++
	s.finishLocked()
	s.mu.Unlock()
}

func (s *ChannelSet) finishLocked() {
	select {
	case <-s.setupDone:
	default:
		return
	}
	if s.finished || s.joined != len(s.servers) {
		return
	}
	s.finished = true
	if !s.cleanupFailed {
		clear(s.descriptors)
		s.descriptors, s.servers, s.handlers = nil, nil, nil
	}
	close(s.done)
}

func channelHandler(handler Handler) broker.Handler {
	var messages int
	return func(ctx context.Context, req wire.Request) wire.Reply {
		messages++
		if messages > MaxRuntimeMessages || len(req.Data) > MaxRequestBytes {
			return fixedFailure()
		}
		frame, err := wire.Encode(wire.Request{Operation: req.Operation, Data: req.Data})
		if err != nil || len(frame) > wire.MaxFrame {
			return fixedFailure()
		}
		var result []byte
		opCtx, cancel := context.WithTimeout(ctx, OperationBudget)
		defer cancel()
		switch req.Operation {
		case "describe":
			var empty struct{}
			if strictDecode(req.Data, &empty) != nil {
				return fixedFailure()
			}
			result, err = safeDescribe(handler, opCtx)
			if err != nil || len(result) > MaxInventoryBytes || !strictJSON(string(result)) {
				return fixedFailure()
			}
		case "call":
			var input callEnvelope
			if strictDecode(req.Data, &input, "tool", "input") != nil || input.Tool == "" || len(input.Tool) > MaxToolBytes || len(input.Input) == 0 || len(input.Input) > MaxClientInputBytes || !strictJSON(input.Input) {
				return fixedFailure()
			}
			result, err = safeCall(handler, opCtx, input.Tool, []byte(input.Input))
			if err != nil || len(result) > MaxResultBytes || !strictJSON(string(result)) {
				return fixedFailure()
			}
		default:
			return fixedFailure()
		}
		reply := wire.Reply{OK: true, Data: string(result)}
		encodedReply, err := wire.Encode(reply)
		if err != nil || len(encodedReply) > wire.MaxFrame {
			return fixedFailure()
		}
		return reply
	}
}

func tokenHex(value string) bool {
	decoded, err := hex.DecodeString(value)
	clear(decoded)
	return err == nil && len(value) == sha256.Size*2 && len(decoded) == sha256.Size
}

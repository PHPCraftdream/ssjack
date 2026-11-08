package mcpbridge

import (
	"context"
	"errors"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/PHPCraftdream/ssjack/internal/buildinfo"
)

type capturingTransport struct {
	base mcp.Transport
	slot *slot
}

func (t *capturingTransport) Connect(context.Context) (mcp.Connection, error) {
	conn, err := t.base.Connect(t.slot.ctx)
	t.slot.lateCaptureClose(conn)
	return conn, err
}

func (r *Runtime) acquireIO(ctx context.Context, s *slot) bool {
	if ctx == nil {
		return false
	}
	select {
	case s.ioGate <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	case <-s.ctx.Done():
		return false
	}
}
func releaseIO(s *slot) { <-s.ioGate }

func (r *Runtime) ensureSession(opCtx context.Context, s *slot) error {
	if opCtx == nil || opCtx.Err() != nil || r.ctx.Err() != nil {
		return errInventory
	}
	r.mu.Lock()
	s.mu.Lock()
	if r.closing || r.ctx.Err() != nil || s.failed {
		s.mu.Unlock()
		r.mu.Unlock()
		return errInventory
	}
	if s.session != nil {
		s.mu.Unlock()
		r.mu.Unlock()
		return nil
	}
	if s.initStarted {
		done := s.initDone
		s.mu.Unlock()
		r.mu.Unlock()
		select {
		case <-done:
		case <-opCtx.Done():
			return errInventory
		case <-r.ctx.Done():
			return errInventory
		}
		return sessionReady(r, s, opCtx)
	}
	s.initStarted = true
	initCtx, initCancel := context.WithTimeout(s.ctx, connectWait)
	stopOperation := context.AfterFunc(opCtx, s.cancel)
	s.mu.Unlock()
	r.mu.Unlock()
	go r.initialize(s, initCtx, initCancel, stopOperation, opCtx)
	select {
	case <-s.initDone:
	case <-opCtx.Done():
		return errInventory
	case <-r.ctx.Done():
		return errInventory
	}
	return sessionReady(r, s, opCtx)
}

func sessionReady(r *Runtime, s *slot, opCtx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.session != nil && !s.failed && opCtx.Err() == nil && r.ctx.Err() == nil {
		return nil
	}
	return errInventory
}

func (r *Runtime) initialize(s *slot, initCtx context.Context, cancel context.CancelFunc, stopOperation func() bool, opCtx context.Context) {
	transport, takeErr := s.handle.TakeTransport()
	if takeErr != nil || transport == nil {
		s.mu.Lock()
		s.failed, s.initErr = true, errInventory
		s.mu.Unlock()
		stopOperation()
		s.cancel()
		cancel()
		close(s.initDone)
		return
	}
	stopConnect := context.AfterFunc(initCtx, s.cancel)
	client := mcp.NewClient(&mcp.Implementation{Name: "ssjack", Version: buildinfo.Version}, nil)
	session, err := client.Connect(initCtx, &capturingTransport{base: transport, slot: s}, nil)
	r.mu.Lock()
	s.mu.Lock()
	valid := err == nil && session != nil && initCtx.Err() == nil && opCtx.Err() == nil && s.ctx.Err() == nil && r.ctx.Err() == nil && !r.closing
	s.mu.Unlock()
	r.mu.Unlock()
	connectStopped := stopConnect()
	operationStopped := stopOperation()
	r.mu.Lock()
	s.mu.Lock()
	valid = valid && connectStopped && operationStopped && initCtx.Err() == nil && opCtx.Err() == nil && s.ctx.Err() == nil && r.ctx.Err() == nil && !r.closing
	if session != nil {
		s.session = session
	}
	if !valid {
		s.failed, s.initErr = true, errInventory
		s.cancel()
	}
	close(s.initDone)
	s.mu.Unlock()
	r.mu.Unlock()
	cancel()
	if !valid {
		s.closeOnce.Do(func() { go s.closeOwned() })
	}
}

// closeOwned closes the captured connection before joining the initializer; a
// wedged Client.Connect unwinds only after that close. Late captures close via
// the capturer, whose error is retained.
func (s *slot) closeOwned() {
	defer close(s.closeDone)
	s.mu.Lock()
	close(s.closeStarted)
	pending := s.conn
	preclose := false
	select {
	case <-s.initDone:
	default:
		preclose = true
	}
	s.mu.Unlock()
	var firstCloseErr error
	if preclose && pending != nil {
		firstCloseErr = pending.Close()
	}
	<-s.initDone
	s.mu.Lock()
	session, conn := s.session, s.conn
	s.mu.Unlock()
	closeErr, waitErr := error(nil), error(nil)
	if session != nil {
		closeErr = session.Close()
		waitErr = session.Wait()
	} else if conn != nil {
		closeErr = conn.Close()
	}
	s.mu.Lock()
	s.closeErr = errors.Join(s.closeErr, firstCloseErr, closeErr, waitErr)
	s.mu.Unlock()
}

func (r *Runtime) failBinding(s *slot) {
	s.cancel()
	s.mu.Lock()
	s.failed = true
	started := s.initStarted
	s.mu.Unlock()
	if started {
		s.closeOnce.Do(func() { go s.closeOwned() })
	}
}

// startShutdown reports the initial cleanup attempt it creates so its creator
// waits on that exact attempt; a later Close retries one failed attempt.
func (r *Runtime) startShutdown() (attempt chan struct{}, fresh bool) {
	r.mu.Lock()
	if !r.closing {
		r.closing = true
		r.cancel()
	}
	slots := append([]*slot(nil), r.slots...)
	if !r.cleanupStarted {
		r.cleanupStarted = true
		attempt = make(chan struct{})
		r.cleanupAttempt = attempt
		fresh = true
		go r.cleanupWorker()
	}
	r.mu.Unlock()
	for _, s := range slots {
		s.cancel()
	}
	return attempt, fresh
}

func (r *Runtime) cleanupWorker() {
	for {
		r.mu.Lock()
		attempt := r.cleanupAttempt
		r.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), DisconnectBudget)
		err, sticky := r.cleanupAttemptRun(ctx)
		cancel()
		r.mu.Lock()
		r.cleanupErr, r.cleanupFinished = err, true
		r.cleanupTerminal = err == nil || sticky
		close(attempt)
		terminal := r.cleanupTerminal
		r.mu.Unlock()
		if terminal {
			return
		}
		attempt = <-r.retryCleanup
		r.mu.Lock()
		r.cleanupAttempt, r.cleanupFinished = attempt, false
		r.mu.Unlock()
	}
}

func (r *Runtime) cleanupAttemptRun(ctx context.Context) (error, bool) {
	r.mu.Lock()
	activeDone := r.activeDone
	slots := append([]*slot(nil), r.slots...)
	r.mu.Unlock()
	if !waitSignal(ctx, activeDone) {
		return ErrBridge, false
	}
	for _, s := range slots {
		s.mu.Lock()
		started := s.initStarted
		s.mu.Unlock()
		if !started {
			continue
		}
		s.closeOnce.Do(func() { go s.closeOwned() })
		if !waitSignal(ctx, s.closeDone) {
			return ErrBridge, false
		}
		s.mu.Lock()
		closeErr := s.closeErr
		s.mu.Unlock()
		if closeErr != nil {
			return ErrBridge, true
		}
	}
	if err := r.closeLaunch(ctx); err != nil {
		return ErrBridge, false
	}
	if ctx.Err() != nil {
		return ErrBridge, false
	}
	return nil, false
}

func waitSignal(ctx context.Context, done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	case <-ctx.Done():
		return false
	}
}

func (r *Runtime) Close(ctx context.Context) error {
	if ctx == nil {
		return ErrBridge
	}
	attempt, fresh := r.startShutdown()
	if !fresh {
		r.mu.Lock()
		attempt = r.cleanupAttempt
		if r.cleanupFinished && !r.cleanupTerminal {
			attempt = make(chan struct{})
			r.cleanupAttempt, r.cleanupFinished = attempt, false
			r.mu.Unlock()
			select {
			case r.retryCleanup <- attempt:
			case <-ctx.Done():
				return ErrBridge
			}
		} else {
			r.mu.Unlock()
		}
	}
	select {
	case <-attempt:
		r.mu.Lock()
		err := r.cleanupErr
		r.mu.Unlock()
		return err
	case <-ctx.Done():
		return ErrBridge
	}
}

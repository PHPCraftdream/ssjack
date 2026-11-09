package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/mcpchannel"
)

type remoteMCPReconnectConnector func(context.Context, mcpchannel.Descriptor, context.CancelFunc) (func(), bool, error)

// This is the shared attempt used by the connected capability control and its
// seam-driven regression. Only the connector varies; admission and evidence do not.
func remoteMCPReconnectAttempt(caller context.Context, encoded string, connect remoteMCPReconnectConnector) bool {
	attempt, cancel := context.WithTimeout(context.Background(), remoteMCPReconnectAttemptBudget)
	defer cancel()
	descriptor, ok := remoteMCPReconnectPreflight(caller, attempt, encoded, time.Now())
	if !ok {
		return false
	}
	callerBeforeErr, attemptBeforeErr := caller.Err(), attempt.Err()
	started := time.Now()
	encodedBefore := encoded
	closeClient, returned, connectErr := connect(attempt, descriptor, cancel)
	ended := time.Now()
	attemptDeadline, _ := attempt.Deadline()
	evidence := remoteMCPReconnectEvidence{
		caller: caller, callerBeforeErr: callerBeforeErr, callerAfterErr: caller.Err(),
		attempt: attempt, attemptBeforeErr: attemptBeforeErr, attemptAfterErr: attempt.Err(),
		attemptDeadline: attemptDeadline, encodedBefore: encodedBefore,
		encodedAfter: encoded, started: started, ended: ended, duration: ended.Sub(started),
		connectErr: connectErr, clientReturned: returned,
	}
	admitted := remoteMCPReconnectEvidenceAdmitted(evidence)
	cancel()
	if closeClient != nil {
		closeClient()
	}
	return admitted
}

func TestRemoteMCPReconnectSharedAttempt(t *testing.T) {
	encoded := remoteMCPReconnectTestDescriptor(t, time.Now(), 30*time.Second)
	descriptor, ok := remoteMCPReconnectDecode(encoded)
	if !ok {
		t.Fatal("test descriptor was invalid")
	}
	assertRefusedWithoutConnect := func(name, channels string, caller context.Context) {
		t.Run(name, func(t *testing.T) {
			called := false
			admitted := remoteMCPReconnectAttempt(caller, channels, func(context.Context, mcpchannel.Descriptor, context.CancelFunc) (func(), bool, error) {
				called = true
				return nil, false, errors.New("synthetic connection failure")
			})
			if called || admitted {
				t.Fatal("spent caller reached connector or earned refusal evidence")
			}
		})
	}
	assertRefusedWithoutConnect("caller already canceled", encoded, canceledRemoteMCPReconnectContext())
	assertRefusedWithoutConnect("nil caller", encoded, nil)
	spentDeadline, cancelSpentDeadline := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelSpentDeadline()
	assertRefusedWithoutConnect("caller with spent deadline", encoded, spentDeadline)
	assertRefusedWithoutConnect("invalid descriptor", "not-a-descriptor", context.Background())

	t.Run("live bounded exact descriptor invokes connector", func(t *testing.T) {
		caller := context.Background()
		called := false
		admitted := remoteMCPReconnectAttempt(caller, encoded, func(attempt context.Context, got mcpchannel.Descriptor, _ context.CancelFunc) (func(), bool, error) {
			called = true
			deadline, bounded := attempt.Deadline()
			if attempt == caller || attempt.Err() != nil || !bounded || !deadline.After(time.Now()) || deadline.Sub(time.Now()) > remoteMCPReconnectAttemptBudget || got != descriptor {
				t.Fatal("connector did not receive the exact descriptor and independent bounded context")
			}
			return nil, false, errors.New("synthetic broker refusal")
		})
		if !called || !admitted {
			t.Fatal("live connector refusal was not admitted as bounded evidence")
		}
	})

	for _, test := range []struct {
		name     string
		cancel   string
		returned bool
		err      error
	}{
		{name: "caller canceled during connect", cancel: "caller", err: errors.New("synthetic refusal")},
		{name: "attempt canceled during connect", cancel: "attempt", err: errors.New("synthetic refusal")},
		{name: "successful client", returned: true},
		{name: "unexpected client with error", returned: true, err: errors.New("synthetic refusal")},
		{name: "live caller with canceled error", err: context.Canceled},
		{name: "live caller with deadline error", err: context.DeadlineExceeded},
	} {
		t.Run(test.name, func(t *testing.T) {
			caller, cancelCaller := context.WithCancel(context.Background())
			defer cancelCaller()
			called, cleaned, callerCancellationIsolated := false, 0, false
			admitted := remoteMCPReconnectAttempt(caller, encoded, func(attempt context.Context, _ mcpchannel.Descriptor, cancelAttempt context.CancelFunc) (func(), bool, error) {
				called = true
				if test.cancel == "caller" {
					cancelCaller()
					callerCancellationIsolated = attempt.Err() == nil
				}
				if test.cancel == "attempt" {
					cancelAttempt()
				}
				return func() { cleaned++ }, test.returned, test.err
			})
			if !called || admitted || cleaned != 1 || test.cancel == "caller" && !callerCancellationIsolated {
				t.Fatal("spent context or client result was credited as refusal, or cleanup was skipped")
			}
		})
	}
}

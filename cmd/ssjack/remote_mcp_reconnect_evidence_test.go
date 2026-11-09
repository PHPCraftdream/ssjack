package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/mcpchannel"
)

const (
	remoteMCPReconnectAttemptBudget = 8 * time.Second
	remoteMCPReconnectBrokerTimeout = 5 * time.Second
	remoteMCPReconnectLeaseMargin   = 14 * time.Second
	remoteMCPReconnectPostMargin    = 9 * time.Second
)

type remoteMCPReconnectEvidence struct {
	caller           context.Context
	callerCancel     context.CancelFunc
	callerBeforeErr  error
	callerAfterErr   error
	attempt          context.Context
	attemptCancel    context.CancelFunc
	attemptBeforeErr error
	attemptAfterErr  error
	attemptDeadline  time.Time
	encodedBefore    string
	encodedAfter     string
	started          time.Time
	ended            time.Time
	duration         time.Duration
	connectErr       error
	clientReturned   bool
}

func remoteMCPReconnectDecode(encoded string) (mcpchannel.Descriptor, bool) {
	descriptors, err := mcpchannel.DecodeDescriptors(encoded)
	if err != nil || len(descriptors) != 1 {
		return mcpchannel.Descriptor{}, false
	}
	canonical, err := mcpchannel.EncodeDescriptors(descriptors)
	if err != nil || canonical != encoded {
		return mcpchannel.Descriptor{}, false
	}
	return descriptors[0], true
}

func remoteMCPReconnectPreflight(caller, attempt context.Context, encoded string, now time.Time) (mcpchannel.Descriptor, bool) {
	if caller == nil || caller.Err() != nil || attempt == nil || attempt.Err() != nil {
		return mcpchannel.Descriptor{}, false
	}
	deadline, ok := attempt.Deadline()
	if !ok || !deadline.After(now) || deadline.Sub(now) > remoteMCPReconnectAttemptBudget {
		return mcpchannel.Descriptor{}, false
	}
	descriptor, ok := remoteMCPReconnectDecode(encoded)
	if !ok || time.Unix(descriptor.ExpiresUnix, 0).Sub(now) < remoteMCPReconnectLeaseMargin {
		return mcpchannel.Descriptor{}, false
	}
	return descriptor, true
}

// The five-second cutoff is conservative refusal of evidence, not attribution of ErrClient to a particular broker or OS failure.
func remoteMCPReconnectEvidenceAdmitted(e remoteMCPReconnectEvidence) bool {
	if e.caller == nil || e.callerBeforeErr != nil || e.callerAfterErr != nil || e.caller.Err() != nil ||
		e.attempt == nil || e.attemptBeforeErr != nil || e.attemptAfterErr != nil || e.attempt.Err() != nil ||
		e.connectErr == nil || errors.Is(e.connectErr, context.Canceled) || errors.Is(e.connectErr, context.DeadlineExceeded) || e.clientReturned || e.duration < 0 || e.duration >= remoteMCPReconnectBrokerTimeout ||
		e.ended.Before(e.started) || e.ended.Sub(e.started) != e.duration {
		return false
	}
	deadline, ok := e.attempt.Deadline()
	if !ok || !deadline.Equal(e.attemptDeadline) || !deadline.After(e.started) || deadline.Sub(e.started) > remoteMCPReconnectAttemptBudget {
		return false
	}
	before, beforeOK := remoteMCPReconnectDecode(e.encodedBefore)
	after, afterOK := remoteMCPReconnectDecode(e.encodedAfter)
	if !beforeOK || !afterOK || e.encodedBefore != e.encodedAfter || before != after {
		return false
	}
	expires := time.Unix(before.ExpiresUnix, 0)
	return expires.Sub(e.started) >= remoteMCPReconnectLeaseMargin && expires.Sub(e.ended) > remoteMCPReconnectPostMargin
}

func TestRemoteMCPReconnectEvidenceAdmission(t *testing.T) {
	cases := []struct {
		name string
		edit func(*testing.T, *remoteMCPReconnectEvidence)
		want bool
	}{
		{name: "live bounded quick error", want: true},
		{name: "exact lease margin", edit: func(t *testing.T, e *remoteMCPReconnectEvidence) {
			e.encodedBefore = remoteMCPReconnectTestDescriptor(t, e.started, 14*time.Second)
			e.encodedAfter = e.encodedBefore
		}, want: true},
		{name: "just under broker timeout", edit: func(t *testing.T, e *remoteMCPReconnectEvidence) {
			e.duration = remoteMCPReconnectBrokerTimeout - time.Nanosecond
			e.ended = e.started.Add(e.duration)
			e.encodedBefore = remoteMCPReconnectTestDescriptor(t, e.started, 16*time.Second)
			e.encodedAfter = e.encodedBefore
		}, want: true},
		{name: "exact post margin overlaps lease margin", edit: func(t *testing.T, e *remoteMCPReconnectEvidence) {
			e.encodedBefore = remoteMCPReconnectTestDescriptor(t, e.started, 10*time.Second)
			e.encodedAfter = e.encodedBefore
		}},
		{name: "lease below margin", edit: func(t *testing.T, e *remoteMCPReconnectEvidence) {
			e.encodedBefore = remoteMCPReconnectTestDescriptor(t, e.started, 13*time.Second)
			e.encodedAfter = e.encodedBefore
		}},
		{name: "expired descriptor", edit: func(t *testing.T, e *remoteMCPReconnectEvidence) {
			e.encodedBefore = remoteMCPReconnectTestDescriptor(t, e.started, -2*time.Minute)
			e.encodedAfter = e.encodedBefore
		}},
		{name: "invalid descriptor after", edit: func(_ *testing.T, e *remoteMCPReconnectEvidence) { e.encodedAfter = "not-a-descriptor" }},
		{name: "changed descriptor", edit: func(t *testing.T, e *remoteMCPReconnectEvidence) {
			e.encodedAfter = remoteMCPReconnectTestDescriptorWithToken(t, e.started, 30*time.Second, "4")
		}},
		{name: "changed encoding", edit: func(_ *testing.T, e *remoteMCPReconnectEvidence) { e.encodedAfter += " " }},
		{name: "successful result without client", edit: func(_ *testing.T, e *remoteMCPReconnectEvidence) { e.connectErr = nil }},
		{name: "unexpected client with error", edit: func(_ *testing.T, e *remoteMCPReconnectEvidence) { e.clientReturned = true }},
		{name: "connect returned canceled", edit: func(_ *testing.T, e *remoteMCPReconnectEvidence) {
			e.connectErr = errors.Join(context.Canceled, errors.New("synthetic detail"))
		}},
		{name: "connect returned deadline exceeded", edit: func(_ *testing.T, e *remoteMCPReconnectEvidence) {
			e.connectErr = errors.Join(context.DeadlineExceeded, errors.New("synthetic detail"))
		}},
		{name: "duration reaches broker timeout", edit: func(_ *testing.T, e *remoteMCPReconnectEvidence) {
			e.duration = remoteMCPReconnectBrokerTimeout
			e.ended = e.started.Add(e.duration)
		}},
		{name: "inconsistent duration", edit: func(_ *testing.T, e *remoteMCPReconnectEvidence) { e.duration++ }},
		{name: "nil caller", edit: func(_ *testing.T, e *remoteMCPReconnectEvidence) { e.caller = nil }},
		{name: "caller spent before attempt", edit: func(_ *testing.T, e *remoteMCPReconnectEvidence) { e.callerBeforeErr = context.Canceled }},
		{name: "caller spent after attempt", edit: func(_ *testing.T, e *remoteMCPReconnectEvidence) { e.callerAfterErr = context.Canceled }},
		{name: "caller canceled", edit: func(_ *testing.T, e *remoteMCPReconnectEvidence) {
			e.callerBeforeErr = context.Canceled
			e.callerAfterErr = context.Canceled
			e.callerCancel()
		}},
		{name: "nil attempt", edit: func(_ *testing.T, e *remoteMCPReconnectEvidence) { e.attempt = nil }},
		{name: "attempt spent before connect", edit: func(_ *testing.T, e *remoteMCPReconnectEvidence) { e.attemptBeforeErr = context.Canceled }},
		{name: "attempt spent after connect", edit: func(_ *testing.T, e *remoteMCPReconnectEvidence) { e.attemptAfterErr = context.Canceled }},
		{name: "attempt canceled", edit: func(_ *testing.T, e *remoteMCPReconnectEvidence) {
			e.attemptBeforeErr = context.Canceled
			e.attemptAfterErr = context.Canceled
			e.attemptCancel()
		}},
		{name: "attempt missing deadline", edit: func(_ *testing.T, e *remoteMCPReconnectEvidence) {
			e.attempt = context.Background()
			e.attemptDeadline = time.Time{}
		}},
		{name: "attempt deadline beyond budget", edit: func(t *testing.T, e *remoteMCPReconnectEvidence) {
			e.attempt, e.attemptCancel, e.attemptDeadline = remoteMCPReconnectTestAttempt(t, e.started.Add(remoteMCPReconnectAttemptBudget+time.Nanosecond))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := remoteMCPReconnectTestEvidence(t, 30*time.Second, time.Second)
			if tc.edit != nil {
				tc.edit(t, &e)
			}
			if got := remoteMCPReconnectEvidenceAdmitted(e); got != tc.want {
				t.Fatal("reconnect evidence admission boundary was incorrect")
			}
		})
	}
}

func TestRemoteMCPReconnectPreflightAdmission(t *testing.T) {
	now := time.Unix(time.Now().Add(time.Minute).Unix(), 0)
	caller, cancelCaller := context.WithCancel(context.Background())
	defer cancelCaller()
	attempt, cancelAttempt := context.WithDeadline(context.Background(), now.Add(remoteMCPReconnectAttemptBudget))
	defer cancelAttempt()
	encoded := remoteMCPReconnectTestDescriptor(t, now, 30*time.Second)
	cases := []struct {
		name    string
		caller  context.Context
		attempt context.Context
		encoded string
		want    bool
	}{
		{name: "live", caller: caller, attempt: attempt, encoded: encoded, want: true},
		{name: "deadline equals preflight time", caller: caller, attempt: func() context.Context {
			c, stop := context.WithDeadline(context.Background(), now)
			t.Cleanup(stop)
			return c
		}(), encoded: encoded},
		{name: "expired attempt deadline", caller: caller, attempt: func() context.Context {
			c, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			t.Cleanup(stop)
			return c
		}(), encoded: encoded},
		{name: "attempt deadline over budget", caller: caller, attempt: func() context.Context {
			c, stop := context.WithDeadline(context.Background(), now.Add(remoteMCPReconnectAttemptBudget+time.Nanosecond))
			t.Cleanup(stop)
			return c
		}(), encoded: encoded},
		{name: "nil caller", attempt: attempt, encoded: encoded},
		{name: "canceled caller", caller: canceledRemoteMCPReconnectContext(), attempt: attempt, encoded: encoded},
		{name: "nil attempt", caller: caller, encoded: encoded},
		{name: "canceled attempt", caller: caller, attempt: canceledRemoteMCPReconnectContext(), encoded: encoded},
		{name: "no attempt deadline", caller: caller, attempt: context.Background(), encoded: encoded},
		{name: "near expiry", caller: caller, attempt: attempt, encoded: remoteMCPReconnectTestDescriptor(t, now, 13*time.Second)},
		{name: "one descriptor required", caller: caller, attempt: attempt, encoded: remoteMCPReconnectMultipleTestDescriptors(t, now)},
		{name: "invalid descriptor", caller: caller, attempt: attempt, encoded: "not-a-descriptor"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, got := remoteMCPReconnectPreflight(tc.caller, tc.attempt, tc.encoded, now)
			if got != tc.want {
				t.Fatal("reconnect preflight admission boundary was incorrect")
			}
		})
	}
}

func canceledRemoteMCPReconnectContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func remoteMCPReconnectTestEvidence(t *testing.T, lease, duration time.Duration) remoteMCPReconnectEvidence {
	t.Helper()
	started := time.Unix(time.Now().Add(time.Minute).Unix(), 0)
	caller, cancelCaller := context.WithCancel(context.Background())
	t.Cleanup(cancelCaller)
	attempt, cancelAttempt, deadline := remoteMCPReconnectTestAttempt(t, started.Add(remoteMCPReconnectAttemptBudget))
	encoded := remoteMCPReconnectTestDescriptor(t, started, lease)
	return remoteMCPReconnectEvidence{caller: caller, callerCancel: cancelCaller, attempt: attempt, attemptCancel: cancelAttempt, attemptDeadline: deadline, callerBeforeErr: caller.Err(), callerAfterErr: caller.Err(), attemptBeforeErr: attempt.Err(), attemptAfterErr: attempt.Err(), encodedBefore: encoded, encodedAfter: encoded, started: started, ended: started.Add(duration), duration: duration, connectErr: errors.New("synthetic bounded failure")}
}

func remoteMCPReconnectTestAttempt(t *testing.T, deadline time.Time) (context.Context, context.CancelFunc, time.Time) {
	t.Helper()
	attempt, cancel := context.WithDeadline(context.Background(), deadline)
	t.Cleanup(cancel)
	actual, _ := attempt.Deadline()
	return attempt, cancel, actual
}

func remoteMCPReconnectTestDescriptor(t *testing.T, started time.Time, lease time.Duration) string {
	return remoteMCPReconnectTestDescriptorWithToken(t, started, lease, "3")
}

func remoteMCPReconnectMultipleTestDescriptors(t *testing.T, started time.Time) string {
	t.Helper()
	one := remoteMCPReconnectTestDescriptorWithToken(t, started, 30*time.Second, "3")
	var descriptors []mcpchannel.Descriptor
	if err := json.Unmarshal([]byte(one), &descriptors); err != nil {
		t.Fatal("test descriptor could not be decoded")
	}
	two := descriptors[0]
	two.Ordinal = 1
	two.Endpoint = "127.0.0.1:47822"
	two.Session = strings.Repeat("5", 64)
	two.Pin = strings.Repeat("6", 64)
	two.Token = strings.Repeat("4", 64)
	encoded, err := json.Marshal(append(descriptors, two))
	if err != nil {
		t.Fatal("multiple test descriptors could not be encoded")
	}
	return string(encoded)
}

func remoteMCPReconnectTestDescriptorWithToken(t *testing.T, started time.Time, lease time.Duration, token string) string {
	t.Helper()
	descriptor := mcpchannel.Descriptor{Version: mcpchannel.VersionRemoteMCP, Ordinal: 0, Session: strings.Repeat("1", 64), Endpoint: "127.0.0.1:47821", Pin: strings.Repeat("2", 64), Token: strings.Repeat(token, 64), ExpiresUnix: started.Unix() + int64(lease/time.Second)}
	encoded, err := mcpchannel.EncodeDescriptors([]mcpchannel.Descriptor{descriptor})
	if err != nil {
		data, marshalErr := json.Marshal([]mcpchannel.Descriptor{descriptor})
		if marshalErr != nil {
			t.Fatal("test descriptor could not be encoded")
		}
		encoded = string(data)
	}
	return encoded
}

package ownercommand

import (
	"errors"
	"strconv"
	"strings"
	"testing"
)

func TestStateResultSeparatesCancelFromUnfinished(t *testing.T) {
	failure := errors.New("synthetic failure")
	for name, tc := range map[string]struct {
		state State
		want  error
	}{
		"finished":            {State{Finished: true}, nil},
		"explicit cancel":     {State{Err: ErrCancelled}, ErrCancelled},
		"failure":             {State{Err: failure}, failure},
		"quit without result": {State{}, ErrIncomplete},
	} {
		t.Run(name, func(t *testing.T) {
			if got := tc.state.Result(); !errors.Is(got, tc.want) || (tc.want == nil) != (got == nil) {
				t.Fatalf("Result()=%v want %v", got, tc.want)
			}
		})
	}
}

func TestStateTraceKeepsTheLastEventsInOrder(t *testing.T) {
	var state State
	for i := 0; i < traceLimit+4; i++ {
		state.Note("k" + strconv.Itoa(i))
	}
	state.Cancel("esc")
	var cancel CancelError
	if !errors.As(state.Result(), &cancel) {
		t.Fatal("Result() is not a CancelError")
	}
	events := strings.Split(cancel.Trace, ",")
	if len(events) != traceLimit {
		t.Fatalf("trace holds %d events, want %d: %q", len(events), traceLimit, cancel.Trace)
	}
	for i, event := range events {
		name, millis, ok := strings.Cut(event, "@")
		if _, err := strconv.ParseInt(millis, 10, 64); !ok || err != nil || name != "k"+strconv.Itoa(i+4) {
			t.Fatalf("event %d is %q, want k%d@<ms>", i, event, i+4)
		}
	}
	var unfinished State
	unfinished.Note("tab")
	var incomplete IncompleteError
	err := unfinished.Result()
	if !errors.Is(err, ErrIncomplete) || !errors.As(err, &incomplete) || !strings.HasPrefix(incomplete.Trace, "tab@") {
		t.Fatalf("Result()=%#v want an IncompleteError with the trace", err)
	}
}

func TestStateCancelCarriesTriggerAndMoves(t *testing.T) {
	state := State{Moves: 2}
	state.Cancel("esc")
	err := state.Result()
	var cancel CancelError
	if !errors.Is(err, ErrCancelled) || !errors.As(err, &cancel) || cancel.Cause != "esc" || cancel.Moves != 2 {
		t.Fatalf("Result()=%#v want a CancelError{esc, 2} that is ErrCancelled", err)
	}
	if err.Error() != ErrCancelled.Error() {
		t.Fatalf("Error()=%q want %q", err.Error(), ErrCancelled.Error())
	}
}

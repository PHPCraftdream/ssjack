package ownercommand

import (
	"errors"
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
			if got := tc.state.Result(); got != tc.want {
				t.Fatalf("Result()=%v want %v", got, tc.want)
			}
		})
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

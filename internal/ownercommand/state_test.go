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

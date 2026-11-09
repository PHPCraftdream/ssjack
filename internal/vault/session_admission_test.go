package vault

import (
	"context"
	"errors"
	"testing"
)

func TestOwnerQueueAdmissionIsRevisionLockedAndDoesNotEdit(t *testing.T) {
	s := newSession(NewDirectory(), func(context.Context, []byte) error { return nil }, func() {})
	defer s.Discard()
	called := false
	admit := func() error {
		called = true
		if s.mu.TryLock() {
			s.mu.Unlock()
			t.Fatal("owner queue admission did not retain the revision lock")
		}
		return nil
	}
	if err := s.AdmitAt(1, admit); !errors.Is(err, ErrOwnerRevision) || called {
		t.Fatal("stale queue admission executed its callback")
	}
	if err := s.AdmitAt(0, admit); err != nil || !called || s.Status().Revision != 0 {
		t.Fatal("queue admission changed the database or refused its displayed revision")
	}
	if err := s.Apply(func(*Vault) error { return nil }); err != nil {
		t.Fatal(err)
	}
	called = false
	if err := s.AdmitAt(0, admit); !errors.Is(err, ErrOwnerRevision) || called {
		t.Fatal("an intervening edit did not invalidate queue admission")
	}
	failure := errors.New("synthetic admission refusal")
	if err := s.AdmitAt(1, func() error { return failure }); !errors.Is(err, failure) || s.Status().Revision != 1 {
		t.Fatal("queue callback failure changed the database revision")
	}
}

func TestOwnerQueueAdmissionRejectsNilClosingAndClosed(t *testing.T) {
	s := newSession(NewDirectory(), func(context.Context, []byte) error { return nil }, func() {})
	defer s.Discard()
	if err := s.AdmitAt(0, nil); err == nil {
		t.Fatal("nil queue callback accepted")
	}
	s.mu.Lock()
	s.closing = true
	s.mu.Unlock()
	called := false
	if err := s.AdmitAt(0, func() error { called = true; return nil }); err == nil || called {
		t.Fatal("closing session admitted new owner work")
	}
	s.Discard()
	if err := s.AdmitAt(0, func() error { called = true; return nil }); err == nil || called {
		t.Fatal("closed session admitted new owner work")
	}
}

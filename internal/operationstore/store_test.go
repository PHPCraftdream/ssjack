package operationstore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func fixture(t *testing.T) (string, *Store) {
	t.Helper()
	if !publicationSupported() {
		t.Skip("durable publication is supported only on Linux")
	}
	p := filepath.Join(t.TempDir(), "state")
	s, e := Initialize(p, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	return p, s
}

func sample(key string) Reservation {
	return Reservation{Key: key, CanonicalTarget: "target", CanonicalResource: "resource", PlanDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
}

func TestInitializeHealthyLifecycle(t *testing.T) {
	if !publicationSupported() {
		t.Skip("durable publication is supported only on Linux")
	}
	root := filepath.Join(t.TempDir(), "state")
	s, err := Initialize(root, time.Second)
	if err != nil {
		t.Fatalf("initialize: %v", err)
	}
	want := sample("existing")
	if got, err := s.Reserve(context.Background(), want); err != nil || got != want {
		t.Fatalf("reserve existing key: %#v, %v", got, err)
	}
	if got, err := s.Lookup(context.Background(), want.Key); err != nil || got != want {
		t.Fatalf("lookup existing key: %#v, %v", got, err)
	}
	if _, err := Open(root, time.Second); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("reopen was not prohibited: %v", err)
	}
}

func TestDuplicateIdempotencyAndChangedBindingConflict(t *testing.T) {
	_, s := fixture(t)
	r := sample("idempotent")
	first, e := s.Reserve(context.Background(), r)
	if e != nil {
		t.Fatal(e)
	}
	second, e := s.Reserve(context.Background(), r)
	if e != nil || first != second {
		t.Fatalf("retry differs: %#v %#v %v", first, second, e)
	}
	different := r
	different.PlanDigest = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	if got, e := s.Reserve(context.Background(), different); !errors.Is(e, ErrConflict) || got != (Reservation{}) {
		t.Fatalf("changed valid binding: %#v %v", got, e)
	}
}

func TestTruncatedStateAndInterruptedTemporaryFailClosed(t *testing.T) {
	_, s := fixture(t)
	if _, e := s.Reserve(context.Background(), sample("valid")); e != nil {
		t.Fatal(e)
	}
	saved, e := os.ReadFile(s.statePath())
	if e != nil {
		t.Fatal(e)
	}
	if _, e := s.Lookup(context.Background(), "valid"); e != nil {
		t.Fatalf("healthy lookup: %v", e)
	}
	if e := os.WriteFile(s.statePath(), []byte(`{"version":1,"records":[`), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Lookup(context.Background(), "valid"); !errors.Is(e, ErrUnavailable) {
		t.Fatalf("truncated state: %v", e)
	}
	if e := os.WriteFile(s.statePath(), saved, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Lookup(context.Background(), "valid"); e != nil {
		t.Fatalf("healthy lookup before .new: %v", e)
	}
	if e := os.WriteFile(s.statePath()+".new", []byte("partial"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Lookup(context.Background(), "valid"); !errors.Is(e, ErrUnavailable) {
		t.Fatalf("interrupted write: %v", e)
	}
}
func TestBoundedLock(t *testing.T) {
	p, s := fixture(t)
	if _, e := s.Reserve(context.Background(), sample("valid")); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Lookup(context.Background(), "valid"); e != nil {
		t.Fatalf("healthy lookup: %v", e)
	}
	lock, e := os.OpenFile(filepath.Join(p, ".lock"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer lock.Close()
	started := make(chan struct{})
	result := make(chan error, 1)
	start := time.Now()
	go func() {
		close(started)
		_, err := s.Lookup(context.Background(), "valid")
		result <- err
	}()
	<-started
	select {
	case e := <-result:
		t.Fatalf("lookup returned before lock timeout: %v", e)
	case <-time.After(100 * time.Millisecond):
	}
	select {
	case e := <-result:
		if !errors.Is(e, ErrUnavailable) {
			t.Fatalf("lookup with held lock: %v", e)
		}
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("lock timeout was not bounded: %v", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("lookup did not time out while lock was held")
	}
}
func TestRestartAndResourceQuarantine(t *testing.T) {
	p, s := fixture(t)
	a := sample("a")
	if _, e := s.Reserve(context.Background(), a); e != nil {
		t.Fatal(e)
	}
	if _, e := Open(p, time.Second); !errors.Is(e, ErrUnavailable) {
		t.Fatalf("reopen was not prohibited: %v", e)
	}
	if _, e := s.Reserve(context.Background(), sample("b")); !errors.Is(e, ErrConflict) {
		t.Fatalf("%v", e)
	}
	for _, k := range []string{"a", "b"} {
		if _, e := s.Lookup(context.Background(), k); !errors.Is(e, ErrConflict) {
			t.Fatalf("%s not quarantined: %v", k, e)
		}
	}
}
func TestExactBindingAndDigest(t *testing.T) {
	_, s := fixture(t)
	r := sample("a")
	if _, e := s.Reserve(context.Background(), r); e != nil {
		t.Fatal(e)
	}
	r.PlanDigest = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
	if _, e := s.Reserve(context.Background(), r); e == nil {
		t.Fatal("accepted non-hex digest")
	}
}
func TestCorruptionAndInjectedWriteFailure(t *testing.T) {
	_, s := fixture(t)
	if _, e := s.Reserve(context.Background(), sample("healthy")); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Lookup(context.Background(), "healthy"); e != nil {
		t.Fatalf("healthy lookup before corruption: %v", e)
	}
	if e := os.WriteFile(s.statePath(), []byte(`{"version":1,"records":[{"key":"healthy","canonical_target":"target","canonical_resource":"resource","plan_digest":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","quarantined":false,"unknown":true}],"quarantined":false}`), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Lookup(context.Background(), "healthy"); !errors.Is(e, ErrUnavailable) {
		t.Fatalf("corruption: %v", e)
	}
	if e := os.WriteFile(s.statePath(), []byte(`{"version":1,"records":[],"quarantined":false}`), 0600); e != nil {
		t.Fatal(e)
	}
	s.saveHook = func(string) error { return errors.New("injected write failure") }
	got, e := s.Reserve(context.Background(), sample("x"))
	if !errors.Is(e, ErrUnavailable) || got != (Reservation{}) {
		t.Fatalf("save failure returned result %#v, %v", got, e)
	}
	if _, e := s.Lookup(context.Background(), "x"); !errors.Is(e, ErrUnavailable) {
		t.Fatalf("failed save visible: %v", e)
	}
}
func TestNoCallerQuarantine(t *testing.T) {
	_, s := fixture(t)
	r := sample("caller-quarantine")
	r.Quarantined = true
	if _, err := s.Reserve(context.Background(), r); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("caller-supplied quarantine: %v", err)
	}
	if _, err := s.Reserve(context.Background(), sample("healthy")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Lookup(context.Background(), "healthy"); err != nil {
		t.Fatalf("healthy lookup: %v", err)
	}
}
func TestRollbackCannotBeDetected(t *testing.T) {
	p, s := fixture(t)
	a := sample("a")
	if _, e := s.Reserve(context.Background(), a); e != nil {
		t.Fatal(e)
	}
	old, e := os.ReadFile(s.statePath())
	if e != nil {
		t.Fatal(e)
	}
	b := sample("b")
	b.CanonicalResource = "other"
	if _, e := s.Reserve(context.Background(), b); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(s.statePath(), old, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Lookup(context.Background(), "a"); e != nil {
		t.Fatalf("live instance did not observe rollback: %v", e)
	}
	if _, e := s.Lookup(context.Background(), "b"); !errors.Is(e, ErrUnavailable) {
		t.Fatalf("live instance did not observe rolled-back state: %v", e)
	}
	if _, e := Open(p, time.Second); !errors.Is(e, ErrUnavailable) {
		t.Fatalf("reopen was not prohibited: %v", e)
	}
}

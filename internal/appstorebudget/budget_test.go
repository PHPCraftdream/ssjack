package appstorebudget_test

import (
	"errors"
	"sync"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstorebudget"
)

func id(value byte) [16]byte { var store [16]byte; store[15] = value; return store }

func TestFixedCapacityScopeAndOldRelease(t *testing.T) {
	if release, err := appstorebudget.TryAcquire([16]byte{}); !errors.Is(err, appstorebudget.ErrInvalid) || release != nil {
		t.Fatal("zero store admitted")
	}
	a, err := appstorebudget.TryAcquire(id(1))
	if err != nil {
		t.Fatal(err)
	}
	defer a()
	if release, err := appstorebudget.TryAcquire(id(1)); !errors.Is(err, appstorebudget.ErrBusy) || release != nil {
		if release != nil {
			release()
		}
		t.Fatal("same store admitted twice")
	}
	b, err := appstorebudget.TryAcquire(id(2))
	if err != nil {
		t.Fatal(err)
	}
	defer b()
	if release, err := appstorebudget.TryAcquire(id(3)); !errors.Is(err, appstorebudget.ErrBusy) || release != nil {
		if release != nil {
			release()
		}
		t.Fatal("third operation admitted")
	}
	a()
	c, err := appstorebudget.TryAcquire(id(3))
	if err != nil {
		t.Fatal(err)
	}
	defer c()
	a()
	if release, err := appstorebudget.TryAcquire(id(4)); !errors.Is(err, appstorebudget.ErrBusy) || release != nil {
		if release != nil {
			release()
		}
		t.Fatal("late release freed a new owner's slot")
	}
}

func TestConcurrentAdmissionHasExactlyTwoHeldOwners(t *testing.T) {
	const total = 8
	start, finish := make(chan struct{}), make(chan struct{})
	results := make(chan error, total)
	var workers sync.WaitGroup
	for i := 0; i < total; i++ {
		workers.Add(1)
		go func(value byte) {
			defer workers.Done()
			<-start
			release, err := appstorebudget.TryAcquire(id(value))
			results <- err
			if err == nil {
				<-finish
				release()
			}
		}(byte(i + 1))
	}
	close(start)
	admitted := 0
	for i := 0; i < total; i++ {
		err := <-results
		if err == nil {
			admitted++
		} else if !errors.Is(err, appstorebudget.ErrBusy) {
			t.Error(err)
		}
	}
	close(finish)
	workers.Wait()
	if admitted != 2 {
		t.Fatalf("held concurrent owners: %d", admitted)
	}
	release, err := appstorebudget.TryAcquire(id(9))
	if err != nil {
		t.Fatal("concurrent owners leaked budget")
	}
	release()
}

func TestConcurrentReleaseCannotFreeNextStore(t *testing.T) {
	release, err := appstorebudget.TryAcquire(id(1))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() { defer workers.Done(); release() }()
	}
	workers.Wait()
	a, err := appstorebudget.TryAcquire(id(1))
	if err != nil {
		t.Fatal(err)
	}
	defer a()
	b, err := appstorebudget.TryAcquire(id(2))
	if err != nil {
		t.Fatal(err)
	}
	defer b()
	release()
	if extra, err := appstorebudget.TryAcquire(id(3)); !errors.Is(err, appstorebudget.ErrBusy) || extra != nil {
		if extra != nil {
			extra()
		}
		t.Fatal("old concurrent release affected new owners")
	}
}

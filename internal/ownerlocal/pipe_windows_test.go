package ownerlocal

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestWindowsPipeAndLifetimeClaimHaveProtectedCurrentUserACLs(t *testing.T) {
	listener, err := Listen(endpointFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	pipe := listener.(*pipeListener)
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid.String()
	for _, claim := range []bool{false, true} {
		handle, kind := pipe.handle, windows.SE_FILE_OBJECT
		if claim {
			handle, kind = pipe.claim, windows.SE_KERNEL_OBJECT
		}
		descriptor, err := windows.GetSecurityInfo(handle, kind, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		owner, _, err := descriptor.Owner()
		if err != nil || owner == nil || owner.String() != sid {
			t.Fatal("owner endpoint belongs to another Windows principal")
		}
		control, _, err := descriptor.Control()
		if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
			t.Fatal("owner endpoint ACL permits inheritance")
		}
		acl, _, err := descriptor.DACL()
		if err != nil || acl == nil || acl.AceCount != 1 || !strings.Contains(descriptor.String(), ";"+sid+")") {
			t.Fatal("owner endpoint ACL admits an additional principal")
		}
	}
}

func TestWindowsOverlappedReadCancellationJoinsKernelCompletion(t *testing.T) {
	_, client, _ := pair(t, endpointFixture(t))
	pipe := client.(*pipeConnection)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	issued := make(chan bool, 1)
	done := make(chan error, 1)
	pipe.mu.Lock()
	pipe.active.Add(1)
	pipe.mu.Unlock()
	go func() {
		defer pipe.active.Done()
		var data [32]byte
		_, err := overlapped(ctx, pipe.handle, data[:], func(overlap *windows.Overlapped, count *uint32) error {
			err := windows.ReadFile(pipe.handle, data[:], count, overlap)
			issued <- errors.Is(err, windows.ERROR_IO_PENDING)
			return err
		})
		done <- err
	}()
	select {
	case pending := <-issued:
		if !pending {
			cancel()
			<-done
			t.Fatal("synthetic Windows read never entered pending kernel I/O")
		}
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("Windows read was not issued")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("cancelled Windows operation did not preserve cancellation")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Windows cancellation did not join kernel I/O")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
}

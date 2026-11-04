package ownerlocal

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
	"unsafe"

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
		handle, kind := pipe.handle, windows.SE_OBJECT_TYPE(windows.SE_FILE_OBJECT)
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
		if err != nil || acl == nil || acl.AceCount != 1 {
			t.Fatal("owner endpoint ACL does not contain exactly one ACE")
		}
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, 0, &ace) != nil || ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 {
			t.Fatal("owner endpoint ACE is not an explicit access allowance")
		}
		offset := int(unsafe.Offsetof(windows.ACCESS_ALLOWED_ACE{}.SidStart))
		if int(ace.Header.AceSize) < offset+8 {
			t.Fatal("owner endpoint ACE has a truncated SID")
		}
		// GetAce owns this in-descriptor SID until descriptor leaves scope.
		header := (*[8]byte)(unsafe.Pointer(&ace.SidStart))
		if offset+8+4*int(header[1]) != int(ace.Header.AceSize) {
			t.Fatal("owner endpoint ACE has an invalid SID length")
		}
		principal := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !principal.Equals(user.User.Sid) {
			t.Fatal("owner endpoint ACE grants another principal access")
		}
		fullAccess := uint32(0x001f01ff) // FILE_ALL_ACCESS.
		if claim {
			fullAccess = 0x001f0003
		} // EVENT_ALL_ACCESS.
		if uint32(ace.Mask) != windows.GENERIC_ALL && uint32(ace.Mask) != fullAccess {
			t.Fatal("owner endpoint ACE has an unexpected access mask")
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

func TestWindowsEndpointUsesNativeCanonicalFilename(t *testing.T) {
	path := endpointFixture(t)
	first, err := Identity(path)
	if err != nil {
		t.Fatal(err)
	}
	alias := strings.TrimSuffix(path, "vault.ktav") + "VAULT.KTAV"
	original, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	alternate, err := os.Stat(alias)
	if os.IsNotExist(err) {
		t.Skip("fixture directory uses case-sensitive filenames")
	}
	if err != nil || !os.SameFile(original, alternate) {
		t.Fatal("case alias does not identify the fixture file")
	}
	second, err := Identity(alias)
	if err != nil || first != second {
		t.Fatal("same Windows file acquired separate endpoints by letter case")
	}
}

package ownerarchive

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func setFixtureDACL(t *testing.T, path, sddl string) {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
}

func TestPrivateWindowsExportDoesNotInheritBroadParentAccess(t *testing.T) {
	parent := t.TempDir()
	setFixtureDACL(t, parent, "D:P(A;OICI;FA;;;WD)")
	path := filepath.Join(parent, "private-export.zip")
	file, err := newPrivateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	identity, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := checkPrivateFile(file, identity); err != nil {
		t.Fatal(err)
	}
	if _, err := newPrivateFile(path); err == nil {
		t.Fatal("Windows export overwrote an existing file")
	}
}

func TestPrivateWindowsExportVerifierRejectsPermissiveACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty-permission-fixture")
	file, err := newPrivateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	setFixtureDACL(t, path, "D:P(A;;FA;;;WD)")
	file, err = os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	identity, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := checkPrivateFile(file, identity); err == nil {
		t.Fatal("owner-only verifier accepted an Everyone grant")
	}
	if identity.Size() != 0 {
		t.Fatal("permission rejection fixture contained private data")
	}
}

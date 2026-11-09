package nativeownercheck

import (
	"context"
	"crypto/sha256"
	"io"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/appstorefile"
)

func verifyPinnedCopy(t *testing.T, ctx context.Context, installation *appstorecrypto.Installation, directory *appstorefile.Directory, commit appstorecrypto.SnapshotCommit) {
	t.Helper()
	tx, err := directory.Lock()
	must(t, err)
	defer tx.Close()
	source, err := tx.OpenSnapshot(commit.State.CommittedSnapshotID())
	must(t, err)
	defer source.Close()
	before, err := appstorefile.Stat(source)
	must(t, err)
	spool, err := tx.Temporary()
	must(t, err)
	defer spool.Close()
	hash := sha256.New()
	copied, err := io.CopyN(io.MultiWriter(spool, hash), source, before.Size)
	must(t, err)
	if copied != before.Size {
		t.Fatal("native pin copy changed ciphertext length")
	}
	var extra [1]byte
	if count, err := source.Read(extra[:]); count != 0 || err != io.EOF {
		t.Fatal("native pin source did not end at its admitted size")
	}
	after, err := appstorefile.Stat(source)
	must(t, err)
	if before != after {
		t.Fatalf("native pin source revision changed (size=%t mtime=%t ctime=%t)", before.Size != after.Size, before.MtimeSec != after.MtimeSec || before.MtimeNsec != after.MtimeNsec, before.CtimeSec != after.CtimeSec || before.CtimeNsec != after.CtimeNsec)
	}
	if string(hash.Sum(nil)) != string(commit.EncodedHash[:]) {
		t.Fatal("native pin copied a different ciphertext digest")
	}
	revision, err := appstorefile.StatTemporary(spool)
	must(t, err)
	if revision.Size != before.Size {
		t.Fatal("native pin spool size differs from its source")
	}
	_, err = spool.Seek(0, io.SeekStart)
	must(t, err)
	_, err = installation.CheckSnapshot(ctx, spool, appstorecrypto.ExpectedSnapshot{StoreID: commit.State.StoreID(), SnapshotID: commit.State.CommittedSnapshotID(), EncodedHash: commit.EncodedHash})
	must(t, err)
	checked, err := appstorefile.StatTemporary(spool)
	must(t, err)
	if checked != revision {
		t.Fatalf("native pin spool revision changed during verification (size=%t mtime=%t ctime=%t)", revision.Size != checked.Size, revision.MtimeSec != checked.MtimeSec || revision.MtimeNsec != checked.MtimeNsec, revision.CtimeSec != checked.CtimeSec || revision.CtimeNsec != checked.CtimeNsec)
	}
	_, err = spool.Seek(0, io.SeekStart)
	must(t, err)
	hash.Reset()
	count, err := io.CopyN(hash, spool, revision.Size)
	must(t, err)
	if count != revision.Size || string(hash.Sum(nil)) != string(commit.EncodedHash[:]) {
		t.Fatal("native pin spool changed ciphertext during second pass")
	}
	checked, err = appstorefile.StatTemporary(spool)
	must(t, err)
	if checked != revision {
		t.Fatal("native pin spool revision changed during second pass")
	}
}

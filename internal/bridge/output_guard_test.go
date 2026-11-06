package bridge

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/outputguard"
	"github.com/PHPCraftdream/ssjack/internal/remote"
)

func TestGuardedCapturePrecedesTextAndOriginalByteBase64(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	secret := []byte{'s', 0, 255, 'e'}
	snapshot, err := outputguard.New([][]byte{secret})
	if err != nil {
		t.Fatal(err)
	}
	manager := remote.NewGuardedManager(ctx, []string{"test"}, func(_ context.Context, _, _ string, stdout, stderr io.Writer) (int, error) {
		for _, value := range append(append([]byte{}, secret...), '|', 254) {
			if _, err := stdout.Write([]byte{value}); err != nil {
				return -1, err
			}
		}
		_, err := stderr.Write(append(append([]byte{}, secret...), '|', 253))
		return 31, err
	}, func(context.Context) (*outputguard.Snapshot, error) { return snapshot, nil })
	defer manager.Close()
	started, err := manager.Start(remote.StartInput{Target: "test", Command: "synthetic"})
	if err != nil {
		t.Fatal(err)
	}
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	var raw remote.ReadOutput
	for {
		raw, err = manager.Read(remote.ReadInput{JobID: started.JobID})
		if err != nil {
			t.Fatal(err)
		}
		if raw.Done {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("guarded bridge fixture did not finish")
		case <-ticker.C:
		}
	}
	out := readOutput(raw)
	stdout, first := base64.StdEncoding.DecodeString(out.StdoutBase64)
	stderr, second := base64.StdEncoding.DecodeString(out.StderrBase64)
	if first != nil || second != nil || !bytes.Equal(stdout, []byte("[REDACTED]|\xfe")) || !bytes.Equal(stderr, []byte("[REDACTED]|\xfd")) || bytes.Contains(stdout, secret) || bytes.Contains(stderr, secret) {
		t.Fatal("model base64 view recovered original captured secret bytes")
	}
	if out.Stdout != "[REDACTED]|�" || out.Stderr != "[REDACTED]|�" || !out.Done || out.ExitCode != 31 || out.Error != "" || out.JobID != started.JobID || out.StdoutOffset != int64(len(stdout)) || out.StderrOffset != int64(len(stderr)) {
		t.Fatal("guarded serialization changed control fields or safe byte representation")
	}
}

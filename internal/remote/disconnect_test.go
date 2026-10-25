package remote

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"storagehost/internal/broker"
	"storagehost/internal/wire"
)

func TestDisconnectCancelsRemoteOperations(t *testing.T) {
	manager := NewManager(context.Background(), []string{"test"}, func(ctx context.Context, _, _ string, _, _ io.Writer) (int, error) {
		<-ctx.Done()
		return -1, ctx.Err()
	})
	defer manager.Close()
	auth := wire.Auth{Version: 2, Session: strings.Repeat("a", 64), Token: strings.Repeat("b", 64)}
	keeper, err := broker.Listen(context.Background(), auth.Session, auth.Token, time.Minute, manager.Handle)
	if err != nil {
		t.Fatal(err)
	}
	defer keeper.Close()
	client, err := broker.Connect(context.Background(), keeper.Endpoint(), keeper.Pin(), auth)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var started StartOutput
	if err := client.Call(context.Background(), "start", StartInput{Target: "test", Command: "wait"}, &started); err != nil {
		t.Fatal(err)
	}
	client.Close()
	awaitJob(t, manager, started.JobID)
	if _, err := manager.Start(StartInput{Target: "test", Command: "again"}); err == nil {
		t.Fatal("new operation started after disconnect")
	}
}

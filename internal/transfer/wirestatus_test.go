package transfer

import (
	"context"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transferengine"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

// TestStatusChunkFieldsCrossTheKeeperWire runs a chunked job through the
// keeper operations and decodes the reply the bridge would receive.
func TestStatusChunkFieldsCrossTheKeeperWire(t *testing.T) {
	fake := &scriptedEngine{}
	fake.set(nil, transferengine.Result{
		Kind: transferengine.KindFile, Files: 1, Bytes: 1048576, SHA256: "aa",
		Mode: transferengine.ModeChunked, ChunkBytes: 262144, ChunksDone: 4, ChunksTotal: 4, Attempts: 6, BytesPerSecond: 12345,
	}, nil)
	m := newManagerWithBuild(t, []string{"t"}, func(string) (Engine, error) { return fake, nil })
	reply, handled := m.Handle(context.Background(), wire.Request{
		Operation: "transfer_upload",
		Data:      mustEncode(t, StartInput{Target: "t", Local: "a", Remote: "/a"}),
	})
	if !handled || !reply.OK {
		t.Fatalf("upload: reply = %+v, handled = %v", reply, handled)
	}
	var started StartOutput
	if err := wire.Decode(reply.Data, &started); err != nil || started.JobID == "" {
		t.Fatalf("upload data = %q, %v", reply.Data, err)
	}
	waitForState(t, m, started.JobID, string(stateDone))
	reply, handled = m.Handle(context.Background(), wire.Request{
		Operation: "transfer_status",
		Data:      mustEncode(t, StatusInput{JobID: started.JobID}),
	})
	if !handled || !reply.OK {
		t.Fatalf("status: reply = %+v, handled = %v", reply, handled)
	}
	var out StatusOutput
	if err := wire.Decode(reply.Data, &out); err != nil {
		t.Fatalf("status data = %q, %v", reply.Data, err)
	}
	if out.State != string(stateDone) || out.Bytes != 1048576 || out.SHA256 != "aa" {
		t.Fatalf("status = %+v", out)
	}
	requireChunk(t, out, "chunked", 262144, 4, 4, 6, 12345)
}

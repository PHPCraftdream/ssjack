package bridge

import (
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/declarativeslice"
	"github.com/PHPCraftdream/ssjack/internal/transfer"
)

const (
	fileHash     = "3f786850e387550fdab836ed7e6dc881de23001b3f786850e387550fdab836ed"
	manifestHash = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
	linkMessage  = "transfer link was too unstable to finish; a retry can resume"
)

func TestRenderTransferStatusGolden(t *testing.T) {
	const id = "05ad9f6712345678abcdef0123456789"
	for _, tc := range []struct {
		name   string
		status transfer.StatusOutput
		want   string
	}{
		{
			name: "running stream",
			status: transfer.StatusOutput{
				JobID: id, State: "running", Direction: "upload", Kind: "file", Phase: "transfer", Mode: "stream",
				Files: 1, Bytes: 156781404, BytesPerSecond: 4200000,
			},
			want: "Transfer " + id + ": upload file, running\n" +
				"Phase: transfer · Mode: stream\n" +
				"Bytes: 156,781,404 · Files: 1 · Dirs: 0 · Speed: 4.2 MB/s\n" +
				"Still running; check again with transfer_status job_id=" + id + " and wait_seconds 20.",
		},
		{
			name: "running chunked",
			status: transfer.StatusOutput{
				JobID: id, State: "running", Direction: "upload", Kind: "file", Phase: "transfer", Mode: "chunked",
				ChunkBytes: 262144, ChunksDone: 12, ChunksTotal: 23, Attempts: 14, Files: 1, Bytes: 3145728, BytesPerSecond: 4200000,
			},
			want: "Transfer " + id + ": upload file, running\n" +
				"Phase: transfer · Mode: chunked · Chunks: 12/23 · Chunk size: 262,144 bytes · Attempts: 14\n" +
				"Bytes: 3,145,728 · Files: 1 · Dirs: 0 · Speed: 4.2 MB/s\n" +
				"Still running; check again with transfer_status job_id=" + id + " and wait_seconds 20.",
		},
		{
			name:   "running before the first byte",
			status: transfer.StatusOutput{JobID: id, State: "running", Direction: "download", Phase: "preflight"},
			want: "Transfer " + id + ": download, running\n" +
				"Phase: preflight\n" +
				"Bytes: 0 · Files: 0 · Dirs: 0\n" +
				"Still running; check again with transfer_status job_id=" + id + " and wait_seconds 20.",
		},
		{
			name: "done file",
			status: transfer.StatusOutput{
				JobID: id, State: "done", Direction: "upload", Kind: "file", Files: 1, Bytes: 1000, SHA256: fileHash,
				Mode: "chunked", ChunkBytes: 262144, ChunksDone: 5, ChunksTotal: 5, Attempts: 5, BytesPerSecond: 1000,
			},
			want: "Transfer " + id + ": upload file, done\n" +
				"Mode: chunked · Chunks: 5/5 · Chunk size: 262,144 bytes · Attempts: 5\n" +
				"Bytes: 1,000 · Files: 1 · Dirs: 0 · Speed: 1.0 kB/s\n" +
				"SHA-256: " + fileHash,
		},
		{
			name: "done directory",
			status: transfer.StatusOutput{
				JobID: id, State: "done", Direction: "download", Kind: "directory", Files: 3, Dirs: 2, Bytes: 4096, ManifestSHA256: manifestHash,
			},
			want: "Transfer " + id + ": download directory, done\n" +
				"Bytes: 4,096 · Files: 3 · Dirs: 2\n" +
				"Manifest SHA-256: " + manifestHash,
		},
		{
			name: "failed link_unstable upload",
			status: transfer.StatusOutput{
				JobID: id, State: "failed", Direction: "upload", Kind: "file", Files: 1, Bytes: 3145728,
				Mode: "chunked", ChunkBytes: 1048576, ChunksDone: 3, ChunksTotal: 9, Attempts: 7,
				ErrorClass: "link_unstable", Message: linkMessage,
			},
			want: "Transfer " + id + ": upload file, failed\n" +
				"Mode: chunked · Chunks: 3/9 · Chunk size: 1,048,576 bytes · Attempts: 7\n" +
				"Bytes: 3,145,728 · Files: 1 · Dirs: 0\n" +
				"Failed: link_unstable — " + linkMessage + "\n" +
				"Resume: call remote_upload again with the same arguments to continue from the staged parts; transfer_cancel removes them instead.",
		},
		{
			name: "failed link_unstable download",
			status: transfer.StatusOutput{
				JobID: id, State: "failed", Direction: "download", Kind: "file", Files: 1, Bytes: 10,
				ErrorClass: "link_unstable", Message: linkMessage,
			},
			want: "Transfer " + id + ": download file, failed\n" +
				"Bytes: 10 · Files: 1 · Dirs: 0\n" +
				"Failed: link_unstable — " + linkMessage + "\n" +
				"Resume: call remote_download again with the same arguments to continue from the staged parts; transfer_cancel removes them instead.",
		},
		{
			name: "cancelled",
			status: transfer.StatusOutput{
				JobID: id, State: "cancelled", Direction: "download", Kind: "file", Files: 1, Bytes: 7,
				ErrorClass: "cancelled", Message: "transfer was cancelled",
			},
			want: "Transfer " + id + ": download file, cancelled\n" +
				"Bytes: 7 · Files: 1 · Dirs: 0\n" +
				"Cancelled: cancelled — transfer was cancelled",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := renderTransferStatus(tc.status)
			if got != tc.want {
				t.Fatalf("rendered\n%s\nwant\n%s", got, tc.want)
			}
			if strings.Contains(got, "…") {
				t.Fatalf("an identifier or hash was abbreviated: %q", got)
			}
			var parsed transfer.StatusOutput
			if err := ParseResult(got, &parsed); err != nil {
				t.Fatal(err)
			}
			if parsed != tc.status {
				t.Fatalf("parsed %+v, want %+v", parsed, tc.status)
			}
		})
	}
}

func TestRenderTransferStatusEveryErrorClass(t *testing.T) {
	for class, message := range map[string]string{
		"refused_path":       "transfer path was refused",
		"exists":             "transfer destination already exists",
		"limit":              "transfer exceeds the configured limits",
		"unsupported_remote": "remote target is missing required transfer tools",
		"integrity":          "transfer failed verification",
		"remote_failed":      "remote operation failed",
		"link_unstable":      linkMessage,
		"cancelled":          "transfer was cancelled",
		"internal":           "transfer failed",
	} {
		t.Run(class, func(t *testing.T) {
			state := "failed"
			if class == "cancelled" {
				state = "cancelled"
			}
			status := transfer.StatusOutput{JobID: "job", State: state, Direction: "upload", Kind: "file", Files: 1, ErrorClass: class, Message: message}
			got := renderTransferStatus(status)
			label := "Failed"
			if state == "cancelled" {
				label = "Cancelled"
			}
			if !strings.Contains(got, "\n"+label+": "+class+" — "+message) {
				t.Fatalf("the failure line is missing: %q", got)
			}
			var parsed transfer.StatusOutput
			if err := ParseResult(got, &parsed); err != nil || parsed != status {
				t.Fatalf("parsed %+v, %v", parsed, err)
			}
		})
	}
}

func TestRenderPlanAndApplyGolden(t *testing.T) {
	revision := "rev-1"
	for _, tc := range []struct {
		name string
		plan declarativeslice.PlanResult
		want string
	}{
		{
			name: "one effect",
			plan: declarativeslice.PlanResult{
				PlanID: "plan1", Digest: "d1", ExpiresAt: "2030-01-02T03:04:05Z", Precondition: &revision,
				Effects: []declarativeslice.Effect{{Class: "cache_metadata", SummaryID: "S1"}},
			},
			want: "Plan plan1 created\nDigest: d1 · Expires: 2030-01-02T03:04:05Z\nPrecondition: rev-1\nEffects: 1\n- cache_metadata: S1\n" +
				"Next: apply it with plan_apply plan_id=plan1 and a new request_id.",
		},
		{
			name: "destructive effects and no precondition",
			plan: declarativeslice.PlanResult{
				PlanID: "plan2", Digest: "d2", ExpiresAt: "2030-01-02T03:04:05Z",
				Effects: []declarativeslice.Effect{{Class: "a", SummaryID: "S1", Destructive: true}, {Class: "b", SummaryID: "S2"}},
			},
			want: "Plan plan2 created\nDigest: d2 · Expires: 2030-01-02T03:04:05Z\nPrecondition: none\nEffects: 2\n- a: S1 (destructive)\n- b: S2\n" +
				"Next: apply it with plan_apply plan_id=plan2 and a new request_id.",
		},
		{
			name: "no effects",
			plan: declarativeslice.PlanResult{PlanID: "plan3", Digest: "d3", ExpiresAt: "2030-01-02T03:04:05Z"},
			want: "Plan plan3 created\nDigest: d3 · Expires: 2030-01-02T03:04:05Z\nPrecondition: none\nEffects: none\n" +
				"Next: apply it with plan_apply plan_id=plan3 and a new request_id.",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := renderPlan(tc.plan)
			if got != tc.want {
				t.Fatalf("rendered\n%s\nwant\n%s", got, tc.want)
			}
			var parsed declarativeslice.PlanResult
			if err := ParseResult(got, &parsed); err != nil {
				t.Fatal(err)
			}
			if parsed.PlanID != tc.plan.PlanID || parsed.Digest != tc.plan.Digest || parsed.ExpiresAt != tc.plan.ExpiresAt || len(parsed.Effects) != len(tc.plan.Effects) {
				t.Fatalf("parsed %+v, want %+v", parsed, tc.plan)
			}
			if (parsed.Precondition == nil) != (tc.plan.Precondition == nil) || (parsed.Precondition != nil && *parsed.Precondition != *tc.plan.Precondition) {
				t.Fatalf("precondition parsed as %v, want %v", parsed.Precondition, tc.plan.Precondition)
			}
			for i, effect := range tc.plan.Effects {
				if parsed.Effects[i] != effect {
					t.Fatalf("effect %d parsed as %+v, want %+v", i, parsed.Effects[i], effect)
				}
			}
		})
	}
	for _, tc := range []struct {
		result declarativeslice.ApplyResult
		want   string
	}{
		{declarativeslice.ApplyResult{OperationID: "op1", State: "SUCCEEDED", Delivery: "RECEIVED"}, "Operation op1: SUCCEEDED\nDelivery: RECEIVED"},
		{declarativeslice.ApplyResult{OperationID: "op2", State: "UNKNOWN", Delivery: "WITHHELD"}, "Operation op2: UNKNOWN\nDelivery: WITHHELD"},
		{declarativeslice.ApplyResult{OperationID: "op3", State: "SUCCEEDED"}, "Operation op3: SUCCEEDED"},
		{declarativeslice.ApplyResult{State: "FAILED"}, "Operation: FAILED"},
	} {
		got := renderApply(tc.result)
		if got != tc.want {
			t.Fatalf("rendered %q, want %q", got, tc.want)
		}
		var parsed declarativeslice.ApplyResult
		if err := ParseResult(got, &parsed); err != nil || parsed != tc.result {
			t.Fatalf("parsed %+v, %v", parsed, err)
		}
	}
}

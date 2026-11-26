package confirm_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/PHPCraftdream/ssjack/internal/application"
	"github.com/PHPCraftdream/ssjack/internal/bridge/internal/confirm"
	tooltext "github.com/PHPCraftdream/ssjack/internal/bridge/internal/tooltext"
	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/transfer"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

type wiringKeeper struct {
	mu            sync.Mutex
	ops           []string
	jobs          int
	classifyError bool
}

func (k *wiringKeeper) handle(_ context.Context, req wire.Request) wire.Reply {
	k.mu.Lock()
	k.ops = append(k.ops, req.Operation)
	k.mu.Unlock()
	switch req.Operation {
	case "app_classify":
		if k.classifyError {
			return wire.Reply{Error: "classification unavailable"}
		}
		var input application.Input
		if err := wire.Decode(req.Data, &input); err != nil || input.Application != "app" || len(input.Arguments) == 0 || input.Arguments[0] != "status" {
			return wire.Reply{Error: "unexpected classification input"}
		}
		return broker.Result(struct {
			NonObservational bool `json:"non_observational"`
		}{true}, nil)
	case "app_list":
		return broker.Result(struct {
			Applications []any `json:"applications"`
		}{[]any{}}, nil)
	case "transfer_upload", "transfer_download":
		k.mu.Lock()
		k.jobs++
		id := k.jobs
		k.mu.Unlock()
		return broker.Result(transfer.StartOutput{JobID: fmt.Sprintf("%064x", id)}, nil)
	case "app_start", "start":
		k.mu.Lock()
		k.jobs++
		k.mu.Unlock()
		return broker.Result(remote.StartOutput{JobID: strings.Repeat("a", 64)}, nil)
	default:
		return wire.Reply{Error: "unexpected operation"}
	}
}

func (k *wiringKeeper) snapshot() ([]string, int) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]string(nil), k.ops...), k.jobs
}

func wiringServer(t *testing.T, ctx context.Context, k *wiringKeeper, manager *confirm.Manager, realConstructor bool) *mcp.Server {
	t.Helper()
	auth := wire.Auth{Version: 2, Session: strings.Repeat("5", 64), Token: strings.Repeat("6", 64)}
	server, err := broker.Listen(ctx, auth.Session, auth.Token, time.Minute, k.handle)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	client, err := broker.Connect(ctx, server.Endpoint(), server.Pin(), auth)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	descriptor := broker.Descriptor{Mode: broker.ModeFull, Protocol: broker.FullProtocol, Complete: true, Tools: []string{"remote_targets", "remote_exec", "remote_read", "remote_cancel", "app_list", "app_exec", "app_read", "app_cancel", "remote_upload", "remote_download", "transfer_status", "transfer_cancel"}}
	if realConstructor {
		built, err := tooltext.NewRegistryForDescriptorWithConfirm(client, descriptor, tooltext.NewConfirmManager(client, func() time.Time { return time.Unix(1, 0) }, nil))
		if err != nil {
			t.Fatal(err)
		}
		return built
	}
	if manager != nil {
		return tooltext.NewFullServerWithClockAndConfirm(client, nil, manager)
	}
	built, err := tooltext.NewRegistryForDescriptor(client, descriptor)
	if err != nil {
		t.Fatal(err)
	}
	return built
}

type wiringRawClient struct {
	conn mcp.Connection
	id   int
}

func wiringClient(t *testing.T, ctx context.Context, server *mcp.Server) *wiringRawClient {
	t.Helper()
	st, ct := mcp.NewInMemoryTransports()
	session, err := server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { session.Close() })
	conn, err := ct.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	c := &wiringRawClient{conn: conn, id: 1}
	init := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"initialize","params":{"protocolVersion":"2026-07-28","capabilities":{},"clientInfo":{"name":"wiring","version":"1"}}}`, c.id)
	c.exchange(t, ctx, init)
	c.id++
	m, err := jsonrpc.DecodeMessage([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Write(ctx, m); err != nil {
		t.Fatal(err)
	}
	return c
}

func (c *wiringRawClient) exchange(t *testing.T, ctx context.Context, payload string) []byte {
	t.Helper()
	msg, err := jsonrpc.DecodeMessage([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.conn.Write(ctx, msg); err != nil {
		t.Fatal(err)
	}
	for {
		incoming, err := c.conn.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if r, ok := incoming.(*jsonrpc.Response); ok {
			b, err := jsonrpc.EncodeMessage(r)
			if err != nil {
				t.Fatal(err)
			}
			return b
		}
	}
}

const wiringModernMeta = `,"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{"elicitation":{"form":{}}}}`
const wiringFormTasksMeta = `,"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{"elicitation":{"form":{}},"extensions":{"io.modelcontextprotocol/tasks":{}}}}`

func (c *wiringRawClient) call(t *testing.T, ctx context.Context, tool, args string, modern bool) []byte {
	t.Helper()
	meta := ""
	if modern {
		meta = wiringModernMeta
	}
	return c.callMeta(t, ctx, tool, args, meta)
}

func (c *wiringRawClient) callMeta(t *testing.T, ctx context.Context, tool, args, meta string) []byte {
	t.Helper()
	payload := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":%q,"arguments":%s%s}}`, c.id, tool, args, meta)
	c.id++
	return c.exchange(t, ctx, payload)
}

func (c *wiringRawClient) callRetry(t *testing.T, ctx context.Context, tool, args, state string) []byte {
	return c.callRetryAction(t, ctx, tool, args, state, "accept")
}

func (c *wiringRawClient) callRetryAction(t *testing.T, ctx context.Context, tool, args, state, action string) []byte {
	return c.callRetryActionMeta(t, ctx, tool, args, state, action, wiringModernMeta)
}

func (c *wiringRawClient) callRetryActionMeta(t *testing.T, ctx context.Context, tool, args, state, action, meta string) []byte {
	t.Helper()
	payload := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":%q,"arguments":%s%s,"inputResponses":{"%s":{"action":%q}},"requestState":%q}}`, c.id, tool, args, meta, confirm.RequestKey, action, state)
	c.id++
	return c.exchange(t, ctx, payload)
}

func wiringIsInputRequired(t *testing.T, data []byte) bool {
	t.Helper()
	var got struct {
		Result struct {
			ResultType    string                     `json:"resultType"`
			RequestState  string                     `json:"requestState"`
			InputRequests map[string]json.RawMessage `json:"inputRequests"`
		} `json:"result"`
	}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Result.ResultType == "input_required" && got.Result.RequestState != "" && len(got.Result.InputRequests) == 1 {
		_, ok := got.Result.InputRequests[confirm.RequestKey]
		return ok
	}
	return false
}

func TestRegistryConstructorWiring(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	upload := `{"target":"allowed","local":"a.bin","remote":"/srv/a.bin","overwrite":true}`
	download := `{"target":"allowed","local":"a.bin","remote":"/srv/a.bin","overwrite":true}`
	t.Run("real constructor enables the gate", func(t *testing.T) {
		keeper := &wiringKeeper{}
		now := func() time.Time { return time.Unix(1, 0) }
		manager := tooltext.NewConfirmManager(nil, now, nil)
		server := wiringServer(t, ctx, keeper, manager, true)
		client := wiringClient(t, ctx, server)
		response := client.call(t, ctx, "remote_upload", upload, true)
		if !wiringIsInputRequired(t, response) {
			t.Fatalf("expected input_required: %s", response)
		}
	})
	t.Run("app_exec_accepted_retry_dispatches_once", func(t *testing.T) {
		keeper := &wiringKeeper{}
		server := wiringServer(t, ctx, keeper, nil, true)
		client := wiringClient(t, ctx, server)
		args := `{"application":"app","arguments":["status"],"confirm":true}`
		response := client.call(t, ctx, "app_exec", args, true)
		if !wiringIsInputRequired(t, response) {
			t.Fatalf("expected input_required: %s", response)
		}
		var stateFrame struct {
			Result struct {
				RequestState string `json:"requestState"`
			} `json:"result"`
		}
		if err := json.Unmarshal(response, &stateFrame); err != nil || stateFrame.Result.RequestState == "" {
			t.Fatalf("could not extract requestState: %s", response)
		}
		retry := client.callRetry(t, ctx, "app_exec", args, stateFrame.Result.RequestState)
		var result struct {
			Result struct {
				IsError bool `json:"isError"`
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"result"`
		}
		if err := json.Unmarshal(retry, &result); err != nil || result.Result.IsError || len(result.Result.Content) != 1 || !strings.Contains(result.Result.Content[0].Text, "Started job ") {
			t.Fatalf("accepted retry did not dispatch: %s", retry)
		}
		ops, jobs := keeper.snapshot()
		if len(ops) != 2 || ops[0] != "app_classify" || ops[1] != "app_start" || jobs != 1 {
			t.Fatalf("operations %v and jobs %d, want app_classify then app_start and one job", ops, jobs)
		}
	})
	t.Run("app_exec_decline_creates_no_job_or_task", func(t *testing.T) {
		keeper := &wiringKeeper{}
		server := wiringServer(t, ctx, keeper, nil, true)
		client := wiringClient(t, ctx, server)
		args := `{"application":"app","arguments":["status"],"confirm":true}`
		response := client.call(t, ctx, "app_exec", args, true)
		var stateFrame struct {
			Result struct {
				RequestState string `json:"requestState"`
			} `json:"result"`
		}
		if err := json.Unmarshal(response, &stateFrame); err != nil || stateFrame.Result.RequestState == "" {
			t.Fatalf("could not extract requestState: %s", response)
		}
		retry := client.callRetryAction(t, ctx, "app_exec", args, stateFrame.Result.RequestState, "decline")
		var result struct {
			Result struct {
				IsError bool `json:"isError"`
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"result"`
		}
		if err := json.Unmarshal(retry, &result); err != nil || !result.Result.IsError || len(result.Result.Content) != 1 || result.Result.Content[0].Text != "operation was not started: declined" {
			t.Fatalf("decline response: %s", retry)
		}
		ops, jobs := keeper.snapshot()
		if len(ops) != 1 || ops[0] != "app_classify" || jobs != 0 {
			t.Fatalf("decline operations %v and jobs %d, want classification only and no job", ops, jobs)
		}
	})
	t.Run("app_exec_form_and_tasks_composition", func(t *testing.T) {
		args := `{"application":"app","arguments":["status"],"confirm":true}`
		t.Run("accepted retry returns task handle", func(t *testing.T) {
			keeper := &wiringKeeper{}
			client := wiringClient(t, ctx, wiringServer(t, ctx, keeper, nil, true))
			response := client.callMeta(t, ctx, "app_exec", args, wiringFormTasksMeta)
			if !wiringIsInputRequired(t, response) {
				t.Fatalf("expected input_required: %s", response)
			}
			var pending struct {
				Result struct {
					RequestState string `json:"requestState"`
				} `json:"result"`
			}
			if err := json.Unmarshal(response, &pending); err != nil || pending.Result.RequestState == "" {
				t.Fatalf("could not extract requestState: %s", response)
			}
			ops, jobs := keeper.snapshot()
			if len(ops) != 1 || ops[0] != "app_classify" || jobs != 0 {
				t.Fatalf("initial operations %v and jobs %d, want classification only", ops, jobs)
			}
			retry := client.callRetryActionMeta(t, ctx, "app_exec", args, pending.Result.RequestState, "accept", wiringFormTasksMeta)
			var handle struct {
				Result struct {
					TaskID string `json:"taskId"`
				} `json:"result"`
			}
			if err := json.Unmarshal(retry, &handle); err != nil || handle.Result.TaskID == "" {
				t.Fatalf("accepted retry did not return task handle: %s", retry)
			}
			ops, jobs = keeper.snapshot()
			if len(ops) != 3 || ops[1] != "app_classify" || ops[2] != "app_start" || jobs != 1 || handle.Result.TaskID != strings.Repeat("a", 64) {
				t.Fatalf("retry operations %v jobs %d taskId %q, want classify/app_start once and minted job id", ops, jobs, handle.Result.TaskID)
			}
		})
		t.Run("declined retry makes no task", func(t *testing.T) {
			keeper := &wiringKeeper{}
			client := wiringClient(t, ctx, wiringServer(t, ctx, keeper, nil, true))
			response := client.callMeta(t, ctx, "app_exec", args, wiringFormTasksMeta)
			var pending struct {
				Result struct {
					RequestState string `json:"requestState"`
				} `json:"result"`
			}
			if !wiringIsInputRequired(t, response) || json.Unmarshal(response, &pending) != nil || pending.Result.RequestState == "" {
				t.Fatalf("expected input_required with requestState: %s", response)
			}
			retry := client.callRetryActionMeta(t, ctx, "app_exec", args, pending.Result.RequestState, "decline", wiringFormTasksMeta)
			var result struct {
				Result struct {
					IsError bool `json:"isError"`
				} `json:"result"`
			}
			if err := json.Unmarshal(retry, &result); err != nil || !result.Result.IsError {
				t.Fatalf("decline response: %s", retry)
			}
			ops, jobs := keeper.snapshot()
			if len(ops) != 1 || ops[0] != "app_classify" || jobs != 0 {
				t.Fatalf("decline operations %v and jobs %d, want classification only", ops, jobs)
			}
			payload := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tasks/get","params":{"taskId":%q,"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{"extensions":{"io.modelcontextprotocol/tasks":{}}}}}}`, client.id, strings.Repeat("a", 64))
			client.id++
			unknown := client.exchange(t, ctx, payload)
			var unknownResult struct {
				Error *struct {
					Code int `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal(unknown, &unknownResult); err != nil || unknownResult.Error == nil || unknownResult.Error.Code != -32602 {
				t.Fatalf("declined retry tasks/get response: %s, want unknown handle", unknown)
			}
		})
	})
	t.Run("download_accepted_retry_dispatches_once", func(t *testing.T) {
		keeper := &wiringKeeper{}
		server := wiringServer(t, ctx, keeper, nil, true)
		client := wiringClient(t, ctx, server)
		args := download
		response := client.call(t, ctx, "remote_download", args, true)
		if !wiringIsInputRequired(t, response) {
			t.Fatalf("expected input_required: %s", response)
		}
		var stateFrame struct {
			Result struct {
				RequestState string `json:"requestState"`
			} `json:"result"`
		}
		if err := json.Unmarshal(response, &stateFrame); err != nil || stateFrame.Result.RequestState == "" {
			t.Fatalf("could not extract requestState: %s", response)
		}
		retry := client.callRetry(t, ctx, "remote_download", args, stateFrame.Result.RequestState)
		var result struct {
			Result struct {
				IsError bool `json:"isError"`
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"result"`
		}
		if err := json.Unmarshal(retry, &result); err != nil || result.Result.IsError || len(result.Result.Content) != 1 || !strings.Contains(result.Result.Content[0].Text, "Started job ") {
			t.Fatalf("accepted retry did not dispatch: %s", retry)
		}
		ops, _ := keeper.snapshot()
		if len(ops) != 1 || ops[0] != "transfer_download" {
			t.Fatalf("operations %v, want one transfer_download", ops)
		}
	})
	t.Run("off default is byte identical", func(t *testing.T) {
		keeper := &wiringKeeper{}
		plain := wiringClient(t, ctx, wiringServer(t, ctx, keeper, nil, false))
		baseline := plain.call(t, ctx, "remote_upload", upload, false)
		managerKeeper := &wiringKeeper{}
		withManager := wiringClient(t, ctx, wiringServer(t, ctx, managerKeeper, confirm.NewManager(nil, nil), false))
		withoutForm := withManager.call(t, ctx, "remote_upload", upload, false)
		if string(baseline) != string(withoutForm) {
			t.Fatalf("pass-through differs: baseline %s, manager %s", baseline, withoutForm)
		}
		for name, frame := range map[string][]byte{"baseline": baseline, "manager": withoutForm} {
			var got struct {
				Result struct {
					IsError bool `json:"isError"`
					Content []struct {
						Text string `json:"text"`
					} `json:"content"`
				} `json:"result"`
			}
			if err := json.Unmarshal(frame, &got); err != nil || got.Result.IsError || len(got.Result.Content) != 1 || !strings.Contains(got.Result.Content[0].Text, "Started job ") {
				t.Fatalf("%s did not dispatch successfully: %s", name, frame)
			}
		}
		for name, k := range map[string]*wiringKeeper{"baseline": keeper, "manager": managerKeeper} {
			ops, _ := k.snapshot()
			if len(ops) != 1 || ops[0] != "transfer_upload" {
				t.Fatalf("%s keeper operations %v, want one transfer_upload", name, ops)
			}
		}
	})
	t.Run("classification has no side effects", func(t *testing.T) {
		keeper := &wiringKeeper{}
		beforeOps, beforeJobs := keeper.snapshot()
		manager := tooltext.NewConfirmManager(nil, nil, nil)
		server := wiringServer(t, ctx, keeper, manager, true)
		client := wiringClient(t, ctx, server)
		args := `{"application":"app","arguments":["status"],"confirm":true}`
		response := client.call(t, ctx, "app_exec", args, true)
		if !wiringIsInputRequired(t, response) {
			t.Fatalf("expected input_required: %s", response)
		}
		afterOps, afterJobs := keeper.snapshot()
		if len(afterOps) != len(beforeOps)+1 || afterOps[len(beforeOps)] != "app_classify" {
			t.Fatalf("operations %v, expected only app_classify", afterOps)
		}
		if afterJobs != beforeJobs {
			t.Fatalf("job counter changed from %d to %d", beforeJobs, afterJobs)
		}
	})
	t.Run("classification failure does not elicit", func(t *testing.T) {
		keeper := &wiringKeeper{classifyError: true}
		manager := tooltext.NewConfirmManager(nil, nil, nil)
		server := wiringServer(t, ctx, keeper, manager, true)
		client := wiringClient(t, ctx, server)
		args := `{"application":"app","arguments":["status"],"confirm":true}`
		response := client.call(t, ctx, "app_exec", args, true)
		if wiringIsInputRequired(t, response) {
			t.Fatalf("classification failure elicited: %s", response)
		}
		ops, jobs := keeper.snapshot()
		if len(ops) != 2 || ops[0] != "app_classify" || ops[1] != "app_start" || jobs != 1 {
			t.Fatalf("operations %v and jobs %d, want classify then app_start", ops, jobs)
		}
	})
}

func jsonEqual(a, b []byte) bool {
	var left, right any
	return json.Unmarshal(a, &left) == nil && json.Unmarshal(b, &right) == nil && fmt.Sprint(left) == fmt.Sprint(right)
}

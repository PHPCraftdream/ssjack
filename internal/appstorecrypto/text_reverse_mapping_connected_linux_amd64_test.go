//go:build linux && amd64

package appstorecrypto_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/apptransport"
	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

const reverseMappingChild = "SSJACK_TEXT_REVERSE_MAPPING_CHILD"

type reverseMappingCase struct {
	Name   string
	Values [][]byte
	Text   string
	Status string
}

func TestTextReverseMappingsConnected(t *testing.T) {
	if os.Getenv(connectedGate) != "1" {
		t.Skip("CI acceptance gate disabled")
	}
	if os.Getenv(reverseMappingChild) == "1" {
		reverseMappingChildRun(t)
		return
	}
	if os.Geteuid() != 0 {
		t.Fatal("connected acceptance parent requires root")
	}
	grantR, grantW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer grantR.Close()
	ackR, ackW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer ackW.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run", "^TestTextReverseMappingsConnected$")
	cmd.Dir = "/tmp"
	cmd.ExtraFiles = []*os.File{grantW, ackR}
	cmd.Env = append(os.Environ(), connectedGate+"=1", reverseMappingChild+"=1", "TMPDIR=/tmp")
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}}
	log := &boundedChildLog{}
	cmd.Stdout = log
	cmd.Stderr = log
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	stop := func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			waited = true
		}
	}
	defer stop()
	defer func() {
		if t.Failed() {
			stop()
			t.Logf("child diagnostics:\n%s", log.String())
		}
	}()
	_ = grantW.Close()
	_ = ackR.Close()
	var grants []declarativeauthority.TextAdapterGrant
	if err = json.NewDecoder(grantR).Decode(&grants); err != nil {
		stop()
		t.Fatalf("read grants: %v", err)
	}
	if len(grants) != 4 {
		stop()
		t.Fatalf("grant count=%d", len(grants))
	}
	if err = declarativeauthority.LoadSetup(); err != nil {
		if err = declarativeauthority.Setup(); err != nil {
			stop()
			t.Fatalf("setup: %v", err)
		}
	}
	for _, grant := range grants {
		if grant.RecipientUID != 65534 {
			stop()
			t.Fatal("unexpected grant recipient")
		}
		if err = declarativeauthority.RegisterTextAdapter(grant); err != nil {
			stop()
			t.Fatalf("register scenario: %v", err)
		}
		defer declarativeauthority.RevokeTextAdapter(grant.ID)
	}
	if _, err = ackW.Write([]byte{1}); err != nil {
		stop()
		t.Fatalf("ack child: %v", err)
	}
	if err = cmd.Wait(); err != nil {
		waited = true
		t.Fatalf("child acceptance: %v\n%s", err, log.String())
	}
	waited = true
}

func reverseMappingChildRun(t *testing.T) {
	grantPipe, ackPipe := os.NewFile(3, "grant"), os.NewFile(4, "ack")
	if grantPipe == nil || ackPipe == nil {
		t.Fatal("missing grant pipes")
	}
	defer grantPipe.Close()
	defer ackPipe.Close()

	cases := []reverseMappingCase{
		{
			Name:   "overlap",
			Values: [][]byte{[]byte("synthetic-long-secret"), []byte("synthetic-long"), []byte("other-value")},
			Text:   "\xef\xbb\xbfπ synthetic-long-secret / synthetic-long / other-value / synthetic-long-secret",
			Status: "received",
		},
		{
			Name:   "equal",
			Values: [][]byte{[]byte("samevalue"), []byte("samevalue")},
			Status: "withheld",
		},
		{
			Name:   "aggregate-overflow",
			Values: [][]byte{bytes.Repeat([]byte("a"), 600<<10), bytes.Repeat([]byte("b"), 600<<10)},
			Status: "withheld",
		},
		{
			Name:   "under-limit",
			Values: [][]byte{[]byte("control-first"), []byte("control-second")},
			Text:   "control-first control-second",
			Status: "received",
		},
	}
	installations := make([]*appstorecrypto.Installation, 0, len(cases))
	grants := make([]declarativeauthority.TextAdapterGrant, 0, len(cases))
	refsByCase := make([][]string, 0, len(cases))
	for _, scenario := range cases {
		installation, grant, refs := appstorecrypto.TextAdapterFixtureValues(t, scenario.Values)
		grant.Mode = "reverse-copy-v1"
		installations = append(installations, installation)
		grants = append(grants, grant)
		refsByCase = append(refsByCase, refs)
	}
	if err := json.NewEncoder(grantPipe).Encode(grants); err != nil {
		t.Fatal(err)
	}
	ack := []byte{0}
	if _, err := io.ReadFull(ackPipe, ack); err != nil || ack[0] != 1 {
		t.Fatalf("parent acknowledgement: %v", err)
	}

	for i, scenario := range cases {
		t.Run(scenario.Name, func(t *testing.T) {
			grant, refs := grants[i], refsByCase[i]
			want := scenario.Text
			if scenario.Name == "overlap" {
				want = "\xef\xbb\xbfπ " + refs[0] + " / " + refs[1] + " / " + refs[2] + " / " + refs[0]
			}
			if scenario.Name == "under-limit" {
				want = refs[0] + " " + refs[1]
			}
			var calls atomic.Int32
			runner := remote.StreamRunner(func(_ context.Context, profile, command string, input io.Reader, stdout, stderr io.Writer) (int, error) {
				calls.Add(1)
				if profile != grant.Profile || command != grant.Command {
					t.Error("unexpected runner profile/command")
				}
				if data, err := io.ReadAll(input); err != nil || len(data) != 0 {
					t.Error("runner stdin was not empty")
				}
				if stderr != io.Discard {
					t.Error("stderr was not discarded")
				}
				if scenario.Status == "withheld" {
					return 0, nil
				}
				split := len(scenario.Text) / 2
				for _, chunk := range [][]byte{[]byte(scenario.Text[:split]), []byte(scenario.Text[split:])} {
					if _, err := stdout.Write(chunk); err != nil {
						return 1, err
					}
				}
				return 0, nil
			})
			adapter, err := appstorecrypto.NewReverseTextAdapter(context.Background(), installations[i], grant.ID, grant.Profile, grant.CredentialSHA256, runner)
			if err != nil {
				t.Fatalf("construct adapter: %v", err)
			}
			defer adapter.Close()
			server, err := apptransport.ListenWithReverseTextAdapter(context.Background(), grant.Profile, runner, adapter)
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer server.Close()

			bootstrap := server.Bootstrap()
			tlsConfig, err := wire.ClientTLS(bootstrap.Pin)
			if err != nil {
				t.Fatal(err)
			}
			client := &http.Client{
				Transport: &http.Transport{TLSClientConfig: tlsConfig},
				Timeout:   10 * time.Second,
			}
			defer client.CloseIdleConnections()
			body, err := json.Marshal(map[string]any{
				"jsonrpc": "2.0",
				"id":      1,
				"method":  "tools/call",
				"params": map[string]any{
					"name": "text_reverse_copy",
					"arguments": map[string]any{
						"operation_id": "AAECAwQFBgcICQoLDA0ODw",
						"file":         grant.File,
						"mode":         grant.Mode,
					},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			doRequest := func(payload []byte) (*http.Response, error) {
				request, err := http.NewRequest(http.MethodPost, bootstrap.Endpoint, bytes.NewReader(payload))
				if err != nil {
					return nil, err
				}
				request.Header.Set("Authorization", "Bearer "+bootstrap.Token)
				request.Header.Set("Content-Type", "application/json")
				request.Header.Set("Accept", "application/json, text/event-stream")
				request.Header.Set("MCP-Protocol-Version", "2025-06-18")
				return client.Do(request)
			}
			type result struct {
				Result struct {
					Structured struct {
						Status string  `json:"status"`
						Text   *string `json:"text"`
					} `json:"structuredContent"`
				} `json:"result"`
			}
			readResponse := func(response *http.Response) ([]byte, result, error) {
				defer response.Body.Close()
				data, err := io.ReadAll(io.LimitReader(response.Body, 25<<20))
				if err != nil {
					return nil, result{}, err
				}
				var decoded result
				if err = json.Unmarshal(data, &decoded); err != nil {
					return data, decoded, err
				}
				if response.StatusCode != http.StatusOK {
					return data, decoded, io.ErrUnexpectedEOF
				}
				return data, decoded, nil
			}
			response, err := doRequest(body)
			if err != nil {
				t.Fatal(err)
			}
			data, decoded, err := readResponse(response)
			if err != nil {
				t.Fatalf("read response: %v", err)
			}
			for _, value := range scenario.Values {
				if bytes.Contains(data, value) {
					t.Fatal("raw response disclosed scenario value")
				}
			}
			if decoded.Result.Structured.Status != scenario.Status {
				t.Fatalf("status=%q, want %q", decoded.Result.Structured.Status, scenario.Status)
			}
			if scenario.Status == "received" {
				if decoded.Result.Structured.Text == nil || *decoded.Result.Structured.Text != want {
					t.Fatal("received text did not match expected placeholder mapping")
				}
			} else if decoded.Result.Structured.Text != nil {
				t.Fatal("withheld response included text")
			}

			before := calls.Load()
			replayResponse, err := doRequest(body)
			if err != nil {
				t.Fatal(err)
			}
			replayData, replayResult, err := readResponse(replayResponse)
			if err != nil {
				t.Fatalf("read replay response: %v", err)
			}
			for _, value := range scenario.Values {
				if bytes.Contains(replayData, value) {
					t.Fatal("raw replay disclosed scenario value")
				}
			}
			if replayResult.Result.Structured.Status != "withheld" || replayResult.Result.Structured.Text != nil {
				t.Fatal("replay was not withheld")
			}
			expectedCalls := int32(0)
			if scenario.Status == "received" {
				expectedCalls = 1
			}
			if calls.Load() != before || before != expectedCalls {
				t.Fatal("replay invoked runner")
			}
		})
	}
}

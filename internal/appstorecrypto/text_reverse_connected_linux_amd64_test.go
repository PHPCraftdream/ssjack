//go:build linux && amd64

package appstorecrypto_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
	"github.com/PHPCraftdream/ssjack/internal/apptransport"
	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

const reverseChild = "SSJACK_TEXT_REVERSE_CHILD"

func TestTextReverseConnected(t *testing.T) {
	if os.Getenv(connectedGate) != "1" {
		t.Skip("CI acceptance gate disabled")
	}
	if os.Getenv(reverseChild) == "1" {
		reverseConnectedChild(t)
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
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run", "^TestTextReverseConnected$")
	cmd.Dir = "/tmp"
	cmd.ExtraFiles = []*os.File{grantW, ackR}
	cmd.Env = append(os.Environ(), connectedGate+"=1", reverseChild+"=1", "TMPDIR=/tmp")
	childLog := &boundedChildLog{}
	cmd.Stdout = childLog
	cmd.Stderr = childLog
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid:    65534,
			Gid:    65534,
			Groups: []uint32{},
		},
	}
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
			t.Logf("child diagnostics:\n%s", childLog.String())
		}
	}()
	_ = grantW.Close()
	_ = ackR.Close()

	var grant declarativeauthority.TextAdapterGrant
	if err = json.NewDecoder(grantR).Decode(&grant); err != nil {
		stop()
		t.Fatalf("read child grant: %v", err)
	}
	if grant.RecipientUID != 65534 {
		stop()
		t.Fatalf("grant recipient UID=%d", grant.RecipientUID)
	}
	if err = declarativeauthority.LoadSetup(); err != nil {
		if err = declarativeauthority.Setup(); err != nil {
			stop()
			t.Fatalf("setup: %v", err)
		}
	}
	if err = declarativeauthority.RegisterTextAdapter(grant); err != nil {
		stop()
		t.Fatalf("register reverse grant: %v", err)
	}
	defer declarativeauthority.RevokeTextAdapter(grant.ID)

	forward := grant
	forward.ID = connectedVariantID(grant.ID, "forward")
	forward.Mode = "hydrate-v1"
	if err = declarativeauthority.RegisterTextAdapter(forward); err != nil {
		stop()
		t.Fatalf("register forward grant: %v", err)
	}
	defer declarativeauthority.RevokeTextAdapter(forward.ID)

	variants := make(map[string]declarativeauthority.TextAdapterGrant)
	register := func(label string, mutate func(*declarativeauthority.TextAdapterGrant)) {
		variant := grant
		variant.References = append([]string(nil), grant.References...)
		variant.ID = connectedVariantID(grant.ID, label)
		mutate(&variant)
		if err = declarativeauthority.RegisterTextAdapter(variant); err != nil {
			stop()
			t.Fatalf("register %s: %v", label, err)
		}
		variants[label] = variant
		t.Cleanup(func() {
			_ = declarativeauthority.RevokeTextAdapter(variant.ID)
		})
	}
	register("wrong-hash", func(g *declarativeauthority.TextAdapterGrant) {
		g.EncodedHash = strings.Repeat("0", 64)
	})
	register("wrong-version", func(g *declarativeauthority.TextAdapterGrant) {
		r, parseErr := appstoreplaceholder.Parse([]byte(g.References[0]))
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		wrong, newErr := appstoreref.New(r.StoreID(), r.ObjectID(), [16]byte{99}, r.SnapshotID())
		if newErr != nil {
			t.Fatal(newErr)
		}
		encoded, encodeErr := appstoreplaceholder.Encode(wrong)
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		g.References[0] = string(encoded)
	})
	register("revoked", func(*declarativeauthority.TextAdapterGrant) {})
	if err = declarativeauthority.RevokeTextAdapter(variants["revoked"].ID); err != nil {
		stop()
		t.Fatalf("revoke revoked variant: %v", err)
	}
	expired := grant
	expired.ID = connectedVariantID(grant.ID, "expired")
	expired.ExpiresAt = time.Now().Add(-time.Second).UTC().Format(time.RFC3339)
	if err = declarativeauthority.RegisterTextAdapter(expired); err == nil {
		_ = declarativeauthority.RevokeTextAdapter(expired.ID)
		stop()
		t.Fatal("registered expired variant")
	}
	if _, err = ackW.Write([]byte{1}); err != nil {
		stop()
		t.Fatalf("ack child: %v", err)
	}
	if err = cmd.Wait(); err != nil {
		waited = true
		t.Fatalf("child acceptance: %v\nchild diagnostics:\n%s", err, childLog.String())
	}
	waited = true
}

func reverseConnectedCancellation(t *testing.T, installation *appstorecrypto.Installation, grant declarativeauthority.TextAdapterGrant) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	runner := remote.StreamRunner(func(runctx context.Context, _ string, _ string, _ io.Reader, stdout, stderr io.Writer) (int, error) {
		calls.Add(1)
		deadline, ok := runctx.Deadline()
		if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > time.Minute {
			t.Errorf("runner context deadline=%v present=%v", deadline, ok)
		}
		cancel()
		_, _ = stdout.Write([]byte(connectedSecret))
		_, _ = stderr.Write([]byte(connectedSecret))
		return 0, nil
	})
	adapter, err := appstorecrypto.NewReverseTextAdapter(context.Background(), installation, grant.ID, grant.Profile, grant.CredentialSHA256, runner)
	if err != nil {
		t.Fatalf("construct cancellation adapter: %v", err)
	}
	defer adapter.Close()
	outcome := adapter.ReverseCopy(ctx, "AAECAwQFBgcICQoLDA0ODw", grant.File)
	if outcome.Status != appstorecrypto.DeliveryUnknown || outcome.Text != nil || calls.Load() != 1 {
		t.Fatalf("cancelled outcome=%+v runner calls=%d", outcome, calls.Load())
	}
	replay := adapter.ReverseCopy(context.Background(), "AAECAwQFBgcICQoLDA0ODw", grant.File)
	if replay.Status != appstorecrypto.DeliveryWithheld || replay.Text != nil || calls.Load() != 1 {
		t.Fatalf("cancelled replay=%+v runner calls=%d", replay, calls.Load())
	}
}

func reverseConnectedChild(t *testing.T) {
	grantPipe := os.NewFile(3, "grant")
	ackPipe := os.NewFile(4, "ack")
	if grantPipe == nil || ackPipe == nil {
		t.Fatal("missing grant pipes")
	}
	defer grantPipe.Close()
	defer ackPipe.Close()

	installation, grant, placeholder := appstorecrypto.TextAdapterFixture(t)
	grant.Mode = "reverse-copy-v1"
	if err := json.NewEncoder(grantPipe).Encode(grant); err != nil {
		t.Fatal(err)
	}
	ack := []byte{0}
	if _, err := io.ReadFull(ackPipe, ack); err != nil || ack[0] != 1 {
		t.Fatalf("parent acknowledgement: %v", err)
	}

	credentialHash := grant.CredentialSHA256
	variants := make(map[string]declarativeauthority.TextAdapterGrant)
	for _, label := range []string{"revoked", "wrong-hash", "wrong-version"} {
		variants[label] = declarativeauthority.TextAdapterGrant{ID: connectedVariantID(grant.ID, label)}
	}
	var calls atomic.Int32
	for _, which := range []string{"wrong-profile", "wrong-credential", "missing-id", "revoked"} {
		t.Run("authority-"+which, func(t *testing.T) {
			calls.Store(0)
			runner := remote.StreamRunner(func(context.Context, string, string, io.Reader, io.Writer, io.Writer) (int, error) {
				calls.Add(1)
				return 0, nil
			})
			profile, credential, id := grant.Profile, credentialHash, grant.ID
			switch which {
			case "wrong-profile":
				profile += "-wrong"
			case "wrong-credential":
				credential = strings.Repeat("0", 64)
			case "missing-id":
				id = connectedVariantID(grant.ID, "missing")
			case "revoked":
				id = variants["revoked"].ID
			}
			if _, err := appstorecrypto.NewReverseTextAdapter(context.Background(), installation, id, profile, credential, runner); err == nil {
				t.Fatal("constructor accepted authority counterfactual")
			}
			if calls.Load() != 0 {
				t.Fatalf("runner calls=%d", calls.Load())
			}
		})
	}
	for _, which := range []string{"wrong-hash", "wrong-version"} {
		t.Run("authority-"+which, func(t *testing.T) {
			calls.Store(0)
			runner := remote.StreamRunner(func(context.Context, string, string, io.Reader, io.Writer, io.Writer) (int, error) {
				calls.Add(1)
				return 0, nil
			})
			adapter, err := appstorecrypto.NewReverseTextAdapter(context.Background(), installation, variants[which].ID, grant.Profile, credentialHash, runner)
			if err != nil {
				t.Fatalf("construct: %v", err)
			}
			defer adapter.Close()
			outcome := adapter.ReverseCopy(context.Background(), "AAECAwQFBgcICQoLDA0ODw", grant.File)
			if outcome.Status != appstorecrypto.DeliveryWithheld || outcome.Text != nil || calls.Load() != 0 {
				t.Fatalf("outcome=%+v runner calls=%d", outcome, calls.Load())
			}
		})
	}
	reverseConnectedCancellation(t, installation, grant)
	reverseConnectedEffectEdges(t, installation, grant)
	t.Run("wrong-file-does-not-consume-attempt", func(t *testing.T) {
		var calls atomic.Int32
		runner := remote.StreamRunner(func(_ context.Context, _ string, _ string, _ io.Reader, stdout, _ io.Writer) (int, error) {
			calls.Add(1)
			_, err := stdout.Write([]byte(connectedSecret))
			return 0, err
		})
		adapter, err := appstorecrypto.NewReverseTextAdapter(context.Background(), installation, grant.ID, grant.Profile, credentialHash, runner)
		if err != nil {
			t.Fatalf("construct: %v", err)
		}
		defer adapter.Close()
		const operationID = "AAECAwQFBgcICQoLDA0ODw"
		wrong := adapter.ReverseCopy(context.Background(), operationID, grant.File+".wrong")
		if wrong.Status != appstorecrypto.DeliveryWithheld || wrong.Text != nil || calls.Load() != 0 {
			t.Fatalf("wrong-file status=%d hasText=%t runner calls=%d", wrong.Status, wrong.Text != nil, calls.Load())
		}
		valid := adapter.ReverseCopy(context.Background(), operationID, grant.File)
		if valid.Status != appstorecrypto.DeliveryReceived || valid.Text == nil || string(valid.Text) != grant.References[0] || calls.Load() != 1 {
			t.Fatalf("valid-file status=%d hasText=%t runner calls=%d", valid.Status, valid.Text != nil, calls.Load())
		}
		clear(valid.Text)
		replay := adapter.ReverseCopy(context.Background(), operationID, grant.File)
		if replay.Status != appstorecrypto.DeliveryWithheld || replay.Text != nil || calls.Load() != 1 {
			t.Fatalf("replay status=%d hasText=%t runner calls=%d", replay.Status, replay.Text != nil, calls.Load())
		}
	})
	for _, which := range []string{"positive", "repeated-unicode", "empty", "ordinary", "error", "nonzero", "overflow", "expansion", "invalid-utf8", "nul", "literal-placeholder", "late-close"} {
		t.Run(which, func(t *testing.T) {
			calls.Store(0)
			runner := remote.StreamRunner(func(_ context.Context, profile, command string, input io.Reader, stdout, stderr io.Writer) (int, error) {
				calls.Add(1)
				if profile != grant.Profile || command != grant.Command {
					t.Errorf("unexpected profile/command")
				}
				in, err := io.ReadAll(input)
				if err != nil || len(in) != 0 {
					t.Errorf("stdin=%q err=%v", in, err)
				}
				if stdout == io.Discard || stderr != io.Discard {
					t.Error("runner streams not configured for private stdout capture")
				}
				_, _ = stderr.Write([]byte(connectedSecret))
				switch which {
				case "positive":
					_, err = stdout.Write([]byte("before " + connectedSecret + " after"))
					return 0, err
				case "repeated-unicode":
					_, _ = stdout.Write([]byte("\xef\xbb\xbfπ before " + connectedSecret[:5]))
					_, err = stdout.Write([]byte(connectedSecret[5:] + " after " + connectedSecret))
					return 0, err
				case "empty":
					return 0, nil
				case "ordinary":
					_, err = stdout.Write([]byte("ordinary π\n"))
					return 0, err
				case "error":
					_, _ = stdout.Write([]byte("before " + connectedSecret + " after"))
					return 0, errors.New(connectedSecret)
				case "nonzero":
					_, _ = stdout.Write([]byte(connectedSecret))
					return 7, nil
				case "overflow":
					_, _ = stdout.Write([]byte(strings.Repeat("x", (1<<20)+1)))
					return 0, nil
				case "expansion":
					_, _ = stdout.Write([]byte(strings.Repeat(connectedSecret, (1<<20)/len(placeholder)+1)))
					return 0, nil
				case "invalid-utf8":
					_, err = stdout.Write([]byte{0xff})
					return 0, err
				case "nul":
					_, err = stdout.Write([]byte("prefix\x00" + connectedSecret))
					return 0, err
				case "literal-placeholder":
					_, err = stdout.Write([]byte(placeholder))
					return 0, err
				default:
					_ = installation.Close()
					_, err = stdout.Write([]byte(connectedSecret))
					return 0, err
				}
			})

			if _, err := appstorecrypto.NewReverseTextAdapter(context.Background(), installation, connectedVariantID(grant.ID, "forward"), grant.Profile, credentialHash, runner); err == nil {
				t.Fatal("reverse constructor accepted forward grant")
			}
			if _, err := appstorecrypto.NewTextAdapter(context.Background(), installation, grant.ID, grant.Profile, credentialHash, runner); err == nil {
				t.Fatal("forward constructor accepted reverse grant")
			}
			adapter, err := appstorecrypto.NewReverseTextAdapter(context.Background(), installation, grant.ID, grant.Profile, credentialHash, runner)
			if err != nil {
				t.Fatalf("construct: %v", err)
			}
			server, err := apptransport.ListenWithReverseTextAdapter(context.Background(), grant.Profile, runner, adapter)
			if err != nil {
				_ = adapter.Close()
				t.Fatalf("listen: %v", err)
			}
			defer func() {
				server.Close()
				_ = adapter.Close()
			}()

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
			response, err := doRequest(body)
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(io.LimitReader(response.Body, 25<<20))
			_ = response.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(data, []byte(connectedSecret)) {
				t.Fatal("raw response disclosed synthetic secret")
			}
			var envelope struct {
				Result struct {
					Structured struct {
						Status string  `json:"status"`
						Text   *string `json:"text"`
					} `json:"structuredContent"`
				} `json:"result"`
			}
			if err = json.Unmarshal(data, &envelope); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if response.StatusCode != http.StatusOK {
				t.Fatalf("HTTP status=%d", response.StatusCode)
			}
			if which == "positive" || which == "repeated-unicode" || which == "empty" || which == "ordinary" {
				want := "before " + placeholder + " after"
				switch which {
				case "repeated-unicode":
					want = "\xef\xbb\xbfπ before " + placeholder + " after " + placeholder
				case "empty":
					want = ""
				case "ordinary":
					want = "ordinary π\n"
				}
				if envelope.Result.Structured.Status != "received" || envelope.Result.Structured.Text == nil || *envelope.Result.Structured.Text != want {
					t.Fatalf("%s result=%+v", which, envelope.Result.Structured)
				}
				before := calls.Load()
				replayResponse, err := doRequest(body)
				if err != nil {
					t.Fatal(err)
				}
				replay, err := io.ReadAll(io.LimitReader(replayResponse.Body, 25<<20))
				_ = replayResponse.Body.Close()
				if err != nil || bytes.Contains(replay, []byte(connectedSecret)) || calls.Load() != before {
					t.Fatalf("replay failed safely: %v", err)
				}
				var replayResult struct {
					Result struct {
						Structured struct {
							Status string  `json:"status"`
							Text   *string `json:"text"`
						} `json:"structuredContent"`
					} `json:"result"`
				}
				if json.Unmarshal(replay, &replayResult) != nil || replayResult.Result.Structured.Status != "withheld" || replayResult.Result.Structured.Text != nil {
					t.Fatal("replay was not withheld")
				}
			} else if envelope.Result.Structured.Status != "unknown" || envelope.Result.Structured.Text != nil {
				t.Fatalf("%s result=%+v", which, envelope.Result.Structured)
			}
			if got := calls.Load(); got != 1 {
				t.Fatalf("runner calls=%d, want 1", got)
			}
		})
	}
}

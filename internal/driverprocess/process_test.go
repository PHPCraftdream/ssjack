package driverprocess

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/driverframe"
	"github.com/PHPCraftdream/ssjack/internal/driverprotocol"
)

const requestJSON = `{"protocol":1,"request_id":"AAAAAAAAAAAAAAAAAAAAAA","action":"observe","target":"node","kind":"service","schema_id":"schema","resource_id":"service.one","desired":null,"expected_revision":null,"plan_digest":null,"allowed_effects":[],"deadline_unix_ms":0,"max_response_bytes":1024,"operation_id":null}`
const responseJSON = `{"protocol":1,"request_id":"AAAAAAAAAAAAAAAAAAAAAA","outcome":"ok","error_code":null,"data":{"state":"present","revision":null,"projection":{}}}`

func TestProcessHelper(t *testing.T) {
	if len(os.Args) < 2 || (os.Args[len(os.Args)-2] != "fixed-test-token" && (len(os.Args) < 3 || os.Args[len(os.Args)-3] != "fixed-test-token")) {
		return
	}
	mode := os.Args[len(os.Args)-1]
	if len(os.Args) >= 3 && os.Args[len(os.Args)-3] == "fixed-test-token" {
		mode = os.Args[len(os.Args)-2]
	}
	if mode == "ready" {
		_, _ = fmt.Fprintln(os.Stderr, os.Getpid())
		time.Sleep(time.Minute)
	}
	if mode == "pid" {
		var b bytes.Buffer
		_, _ = fmt.Fprint(&b, os.Getpid())
		_ = driverframe.Write(os.Stdout, b.Bytes())
		os.Exit(0)
	}
	if _, err := io.ReadAll(os.Stdin); err != nil {
		os.Exit(92)
	}
	switch mode {
	case "zero-length":
		_, _ = os.Stdout.Write([]byte{0, 0, 0, 0})
		os.Exit(0)
	case "trailing-byte":
		_ = driverframe.Write(os.Stdout, []byte(responseJSON))
		_, _ = os.Stdout.Write([]byte{0})
		os.Exit(0)
	case "invalid-json":
		_ = driverframe.Write(os.Stdout, []byte("not-json"))
		os.Exit(0)
	case "wrong-correlation":
		_ = driverframe.Write(os.Stdout, []byte(bytes.Replace([]byte(responseJSON), []byte("AAAAAAAAAAAAAAAAAAAAAA"), []byte("BBBBBBBBBBBBBBBBBBBBBB"), 1)))
		os.Exit(0)
	case "maximum":
		payload := []byte(responseJSON)
		payload = append(payload, bytes.Repeat([]byte(" "), driverframe.MaxPayload-len(payload))...)
		_ = driverframe.Write(os.Stdout, payload)
		os.Exit(0)
	case "malformed":
		_ = driverframe.Write(os.Stdout, []byte("not-json"))
		os.Exit(0)
	case "badframe":
		_, _ = os.Stdout.Write([]byte{0, 0, 0, 0})
		os.Exit(0)
	case "extra":
		_ = driverframe.Write(os.Stdout, []byte(responseJSON))
		_ = driverframe.Write(os.Stdout, []byte(`{}`))
		os.Exit(0)
	case "overflow-block":
		_, _ = os.Stdout.Write(make([]byte, MaxOutput+1))
		time.Sleep(time.Minute)
		os.Exit(0)
	case "overflow":
		_, _ = os.Stdout.Write(make([]byte, MaxOutput+1))
		os.Exit(0)
	case "stderr":
		_, _ = os.Stderr.Write(make([]byte, MaxOutput+1))
		os.Exit(0)
	case "sleep":
		time.Sleep(time.Minute)
	case "fail":
		_ = driverframe.Write(os.Stdout, []byte(responseJSON))
		os.Exit(7)
	case "env":
		if os.Getenv("SECRET_LEAK") != "" {
			os.Exit(93)
		}
	}
	_ = driverframe.Write(os.Stdout, []byte(responseJSON))
	os.Exit(0)
}

type testCapability struct{ mode string }

func (c testCapability) command(ctx context.Context) *exec.Cmd {
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=TestProcessHelper", "--", "fixed-test-token", c.mode)
	return testCommandEnvironment(cmd)
}

func testCommandEnvironment(cmd *exec.Cmd) *exec.Cmd {
	// On Windows os/exec adds SYSTEMROOT if absent from this replacement environment.
	env := []string{"LANG=C", "LC_ALL=C"}
	if os.Getenv("SystemRoot") != "" {
		env = append(env, "SystemRoot="+os.Getenv("SystemRoot"))
	}
	cmd.Env = env
	return cmd
}
func launch(ctx context.Context, mode string, request []byte) (Result, error) {
	return execute(ctx, testCapability{mode: mode}, request)
}

func TestProcessTransport(t *testing.T) {
	q, e := driverprotocol.ValidateStructuralRequest([]byte(requestJSON))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = driverprotocol.ValidateStructuralResponse(q, []byte(responseJSON)); e != nil {
		t.Fatal(e)
	}
	for _, mode := range []string{"ok", "env"} {
		if mode == "env" {
			t.Setenv("SECRET_LEAK", "hidden")
		}
		ctx, c := context.WithTimeout(context.Background(), 4*time.Second)
		r, e := launch(ctx, mode, []byte(requestJSON))
		c()
		if e != nil || r.ExitErr != nil {
			t.Fatalf("%s: %+v %v", mode, r, e)
		}
	}
	for _, tc := range []struct {
		mode string
		want error
	}{{"malformed", ErrSemantic}, {"badframe", ErrSemantic}, {"extra", ErrSemantic}, {"overflow", ErrOutputLimit}, {"stderr", ErrOutputLimit}} {
		ctx, c := context.WithTimeout(context.Background(), 4*time.Second)
		r, e := launch(ctx, tc.mode, []byte(requestJSON))
		c()
		if !errors.Is(e, tc.want) {
			t.Errorf("%s: %v", tc.mode, e)
		}
		if tc.want == ErrSemantic && r.SemanticErr == nil {
			t.Errorf("missing semantic error %s", tc.mode)
		}
	}
	ctx, c := context.WithTimeout(context.Background(), 4*time.Second)
	r, e := launch(ctx, "fail", []byte(requestJSON))
	c()
	if e == nil || r.ExitErr == nil || r.SemanticErr != nil {
		t.Fatalf("nonzero exit: %+v %v", r, e)
	}
}
func TestProcessContext(t *testing.T) {
	if _, e := Execute(context.Background(), "ignored", nil, nil); !errors.Is(e, ErrUnsupported) {
		t.Fatal(e)
	}
	if _, e := launch(context.Background(), "ok", []byte(requestJSON)); !errors.Is(e, ErrDeadlineRequired) {
		t.Fatal(e)
	}
	ctx, c := context.WithCancel(context.Background())
	c()
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if _, e := launch(ctx, "sleep", []byte(requestJSON)); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel2()
	start := time.Now()
	r, e := launch(ctx2, "sleep", []byte(requestJSON))
	if !errors.Is(e, context.DeadlineExceeded) || r.ExitErr == nil || time.Since(start) > 5*time.Second {
		t.Fatalf("deadline: %+v %v", r, e)
	}
}

type readOnlySource struct{ data []byte }

func (r *readOnlySource) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}
func TestCopyPaths(t *testing.T) {
	w := &cappedBuffer{limit: 4}
	n, e := io.Copy(w, &readOnlySource{data: []byte("123456")})
	if !errors.Is(e, ErrOutputLimit) || n != 4 || len(w.Bytes()) != 4 || !w.exceeded {
		t.Fatalf("Reader: %d %v", n, e)
	}
	w = &cappedBuffer{limit: 4}
	n, e = io.Copy(w, bytes.NewReader([]byte("123456")))
	if !errors.Is(e, ErrOutputLimit) || n != 4 || len(w.Bytes()) != 4 || !w.exceeded {
		t.Fatalf("WriterTo: %d %v", n, e)
	}
}

package broker

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/enrollment"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

func fixture(t *testing.T) (*Server, wire.Auth) {
	t.Helper()
	auth := wire.Auth{Version: 2, Session: strings.Repeat("1", 64), Token: strings.Repeat("2", 64)}
	s, err := Listen(context.Background(), auth.Session, auth.Token, time.Minute, func(_ context.Context, req wire.Request) wire.Reply {
		return wire.Reply{OK: true, Data: req.Data}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s, auth
}

func TestFullCompatibilityAndInvalidDescriptor(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	auth := wire.Auth{Version: 2, Session: strings.Repeat("c", 64), Token: strings.Repeat("d", 64)}
	called := false
	handler := Dispatch(ModeFull, func(context.Context, wire.Request) wire.Reply {
		called = true
		return Result(map[string]string{"ok": "yes"}, nil)
	})
	keeper, err := Listen(ctx, auth.Session, auth.Token, time.Minute, handler)
	if err != nil {
		t.Fatal(err)
	}
	defer keeper.Close()
	client, err := Connect(ctx, keeper.Endpoint(), keeper.Pin(), auth)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	d, err := Describe(ctx, client)
	if err != nil || d.Mode != ModeFull || !d.Complete || len(d.Tools) != 12 {
		t.Fatalf("full descriptor: %+v %v", d, err)
	}
	var response map[string]string
	if err := client.Call(ctx, "legacy-op", struct{}{}, &response); err != nil || response["ok"] != "yes" || !called {
		t.Fatal("full compatibility path failed")
	}
	called = false
	if err := client.Call(ctx, "session.describe", map[string]any{"discovery": DiscoveryRequest, "mode": "declarative"}, &response); err == nil {
		t.Fatal("accepted mode switch attempt")
	}
	d, err = Describe(ctx, client)
	if err != nil || d.Mode != ModeFull || !d.Complete || len(d.Tools) != 12 {
		t.Fatalf("mode changed after rejected attempt: %+v %v", d, err)
	}
	if called {
		t.Fatal("mode-switch attempt invoked full callback")
	}
}

func TestRequiresTokenSessionAndProtocolVersion(t *testing.T) {
	s, auth := fixture(t)
	for _, field := range []string{"token", "version", "session"} {
		bad := auth
		switch field {
		case "token":
			bad.Token = strings.Repeat("0", 64)
		case "version":
			bad.Version = 1
		case "session":
			bad.Session = strings.Repeat("0", 64)
		}
		if c, err := Connect(context.Background(), s.Endpoint(), s.Pin(), bad); err == nil {
			c.Close()
			t.Fatalf("accepted incorrect %s", field)
		}
	}
	c, err := Connect(context.Background(), s.Endpoint(), s.Pin(), auth)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var got map[string]string
	if err := c.Call(context.Background(), "echo", map[string]string{"value": "data"}, &got); err != nil || got["value"] != "data" {
		t.Fatalf("unexpected response: %v, %v", got, err)
	}
}

func TestRejectWrongCertificateWithoutConsuming(t *testing.T) {
	s, auth := fixture(t)
	if c, err := Connect(context.Background(), s.Endpoint(), strings.Repeat("0", 64), auth); err == nil {
		c.Close()
		t.Fatal("accepted an untrusted certificate")
	}
	c, err := Connect(context.Background(), s.Endpoint(), s.Pin(), auth)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}

func TestExactlyOneConcurrentAttachAndNoReplay(t *testing.T) {
	s, auth := fixture(t)
	start := make(chan struct{})
	results := make(chan *Client, 8)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			c, _ := Connect(context.Background(), s.Endpoint(), s.Pin(), auth)
			results <- c
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	var winner *Client
	for c := range results {
		if c != nil {
			if winner != nil {
				c.Close()
				t.Fatal("two clients obtained access")
			}
			winner = c
		}
	}
	if winner == nil {
		t.Fatal("no client obtained access")
	}
	winner.Close()
	select {
	case <-s.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("disconnect did not close the session")
	}
	if c, err := Connect(context.Background(), s.Endpoint(), s.Pin(), auth); err == nil {
		c.Close()
		t.Fatal("replay was allowed")
	}
}

func TestAttachedSessionOutlivesBootstrapDeadline(t *testing.T) {
	auth := wire.Auth{Version: 2, Session: strings.Repeat("1", 64), Token: strings.Repeat("2", 64)}
	s, err := Listen(context.Background(), auth.Session, auth.Token, 2*time.Second, func(_ context.Context, req wire.Request) wire.Reply {
		return wire.Reply{OK: true, Data: req.Data}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	client, err := Connect(context.Background(), s.Endpoint(), s.Pin(), auth)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	timer := time.NewTimer(time.Until(s.expires) + 50*time.Millisecond)
	defer timer.Stop()
	select {
	case <-s.Done():
		t.Fatal("bootstrap timer closed an attached session")
	case <-timer.C:
	}
	if err := client.Call(context.Background(), "echo", struct{}{}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestMemoryBootstrap(t *testing.T) {
	s, auth := fixture(t)
	bootstrap := Bootstrap{Session: auth.Session, Endpoint: s.Endpoint(), Pin: s.Pin(), Token: auth.Token}
	bad := bootstrap
	bad.Token = strings.Repeat("0", 64)
	if client, err := ConnectBootstrap(context.Background(), bad); err == nil {
		client.Close()
		t.Fatal("wrong token accepted")
	}
	client, err := ConnectBootstrap(context.Background(), bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Call(context.Background(), "echo", struct{}{}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestExpiryAndRejectedMemoryBootstrap(t *testing.T) {
	s, err := Listen(context.Background(), strings.Repeat("1", 64), strings.Repeat("2", 64), time.Millisecond, func(context.Context, wire.Request) wire.Reply { return wire.Reply{OK: true} })
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	select {
	case <-s.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("bootstrap did not expire")
	}
	for _, token := range []string{"", "secret", strings.Repeat("z", 64)} {
		if _, err := ConnectBootstrap(context.Background(), Bootstrap{Session: strings.Repeat("1", 64), Token: token}); err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatal("invalid token accepted or exposed")
		}
	}
}

func TestCancellationAndHandlerError(t *testing.T) {
	s, auth := fixture(t)
	client, err := Connect(context.Background(), s.Endpoint(), s.Pin(), auth)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := client.Call(ctx, "echo", nil, nil); err == nil {
		t.Fatal("cancelled request was executed")
	}
	reply := Result(nil, context.Canceled)
	if reply.OK || reply.Error == "" {
		t.Fatal("handler error was lost")
	}
	var raw map[string]int
	if err := client.Call(context.Background(), "echo", map[string]int{"n": 1}, &raw); err != nil {
		t.Fatal(err)
	}
}

func TestRejectNoncanonicalEndpointsBeforeTLSOrDial(t *testing.T) {
	for _, endpoint := range []string{
		"192.0.2.1:443", "0.0.0.0:1234", "localhost:1234", "127.0.0.1.example:1234",
		"[::1]:1234", "[::ffff:127.0.0.1]:1234", "[::]:1234", "2130706433:1234",
		"127.0.0.1:http", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:+22", "127.0.0.1",
	} {
		if _, err := Connect(context.Background(), endpoint, "invalid pin", wire.Auth{}); err == nil || !strings.Contains(err.Error(), "keeper endpoint") {
			t.Fatalf("endpoint reached TLS validation or dial: %q: %v", endpoint, err)
		}
	}
	for _, endpoint := range []string{"127.0.0.1:1", "127.0.0.1:65535"} {
		if err := validateEndpoint(endpoint); err != nil {
			t.Fatalf("valid endpoint rejected: %q: %v", endpoint, err)
		}
	}
}

func TestOnlyTCPRemoteLoopbackPeersAreAccepted(t *testing.T) {
	for _, address := range []net.Addr{nil, (*net.TCPAddr)(nil), &net.IPAddr{IP: net.ParseIP("127.0.0.1")}, &net.TCPAddr{IP: net.ParseIP("192.0.2.1")}, &net.TCPAddr{IP: net.IPv4zero}} {
		if loopbackPeer(address) {
			t.Fatalf("non-loopback TCP peer accepted: %v", address)
		}
	}
	for _, ip := range []string{"127.0.0.1", "::1", "::ffff:127.0.0.1"} {
		if !loopbackPeer(&net.TCPAddr{IP: net.ParseIP(ip), Port: 12345}) {
			t.Fatalf("loopback peer rejected: %s", ip)
		}
	}
}

func identityFixtures(t *testing.T) (enrollment.Metadata, enrollment.Policy, enrollment.Snapshot) {
	t.Helper()
	id := "AAAAAAAAAAAAAAAAAAAAAA"
	metadata, err := enrollment.Parse([]byte(`{"format":"ssjack-enrollment-metadata-v1","enrollment_id":"` + id + `","driver_id":"driver-a","driver_protocol":1}`))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := enrollment.ParsePolicy([]byte(`{"format":"ssjack-policy-subset-v1","enrollment_id":"`+id+`","driver_id":"driver-a","driver_protocol":1,"revision":"r1"}`), metadata)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte(`{"format":"ssjack-enrollment-identity-subset-v1","enrollment_id":"` + id + `","driver_id":"driver-a","driver_protocol":1,"executable":{"path":"/opt/driver","sha256":"` + strings.Repeat("a", 64) + `"},"artifact_digests":{"main":"` + strings.Repeat("b", 64) + `"},"dependency_digests":{},"configuration_digest":"` + strings.Repeat("c", 64) + `","principal":{"issuer":"local","subject":"operator"}}`)
	snapshot, err := enrollment.ParseSnapshot(data, metadata, policy)
	if err != nil {
		t.Fatal(err)
	}
	return metadata, policy, snapshot
}

func TestDispatchIdentityBindingAndDeny(t *testing.T) {
	metadata, policy, snapshot := identityFixtures(t)
	if _, err := DispatchIdentity(nil, policy, snapshot); err == nil {
		t.Fatal("accepted nil metadata")
	}
	other, err := enrollment.ParsePolicy([]byte(`{"format":"ssjack-policy-subset-v1","enrollment_id":"AAAAAAAAAAAAAAAAAAAAAA","driver_id":"driver-a","driver_protocol":1,"revision":"r2"}`), metadata)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DispatchIdentity(&metadata, other, snapshot); err == nil {
		t.Fatal("accepted snapshot bound to incompatible policy")
	}
	changedRawPolicy, err := enrollment.ParsePolicy([]byte(`{ "format":"ssjack-policy-subset-v1","enrollment_id":"AAAAAAAAAAAAAAAAAAAAAA","driver_id":"driver-a","driver_protocol":1,"revision":"r1"}`), metadata)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DispatchIdentity(&metadata, changedRawPolicy, snapshot); err == nil {
		t.Fatal("accepted same-revision policy with changed raw bytes")
	}
	h, err := DispatchIdentity(&metadata, policy, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := wire.Encode(DescribeRequest{Discovery: DiscoveryRequest})
	reply := h(context.Background(), wire.Request{Operation: "session.describe", Data: request})
	if !reply.OK {
		t.Fatalf("describe failed: %s", reply.Error)
	}
	var d Descriptor
	if err := wire.DecodeStrict(reply.Data, &d, "protocol", "mode", "complete", "tools", "enrollment_id", "driver_id", "driver_protocol", "policy_revision", "policy_digest", "snapshot_digest"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateDescriptor(d); err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{"targets", "remote_exec", "app_start", "driver.execute", "session.other"} {
		if h(context.Background(), wire.Request{Operation: op}).OK {
			t.Fatalf("accepted operation %q", op)
		}
	}
	forged := d
	forged.SnapshotDigest = "../../" + strings.Repeat("a", 64)
	if ValidateDescriptor(forged) == nil {
		t.Fatal("accepted forged snapshot digest")
	}
	forged = d
	forged.Tools = []string{"remote_exec"}
	if ValidateDescriptor(forged) == nil {
		t.Fatal("accepted snapshot descriptor with tools")
	}
}

func TestOldDescriptorsRejectSnapshotDigest(t *testing.T) {
	cases := []Descriptor{
		{Protocol: FullProtocol, Mode: ModeFull, Complete: true, Tools: []string{"remote_targets", "remote_exec", "remote_read", "remote_cancel", "app_list", "app_exec", "app_read", "app_cancel", "remote_upload", "remote_download", "transfer_status", "transfer_cancel"}, SnapshotDigest: strings.Repeat("a", 64)},
		{Protocol: PartialProtocol, Mode: ModeDeclarative, Tools: []string{}, SnapshotDigest: strings.Repeat("a", 64)},
		{Protocol: EnrollmentProtocol, Mode: ModeDeclarative, Tools: []string{}, EnrollmentID: "AAAAAAAAAAAAAAAAAAAAAA", DriverID: "driver-a", DriverProtocol: 1, SnapshotDigest: strings.Repeat("a", 64)},
		{Protocol: PolicyProtocol, Mode: ModeDeclarative, Tools: []string{}, EnrollmentID: "AAAAAAAAAAAAAAAAAAAAAA", DriverID: "driver-a", DriverProtocol: 1, PolicyRevision: "r1", PolicyDigest: strings.Repeat("a", 64), SnapshotDigest: strings.Repeat("a", 64)},
	}
	for _, d := range cases {
		if ValidateDescriptor(d) == nil {
			t.Fatalf("accepted old descriptor with snapshot digest: %+v", d)
		}
	}
}

type traceRecorder struct {
	mu     sync.Mutex
	events []string
}

func (r *traceRecorder) record(event string, pairs ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event+" "+strings.Join(pairs, " "))
}

func (r *traceRecorder) find(prefix string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, event := range r.events {
		if strings.HasPrefix(event, prefix) {
			return event
		}
	}
	return ""
}

func TestTraceExplainsWhyTheChannelEnded(t *testing.T) {
	auth := wire.Auth{Version: 2, Session: strings.Repeat("7", 64), Token: strings.Repeat("8", 64)}
	recorder := &traceRecorder{}
	keeper, err := ListenTraced(context.Background(), auth.Session, auth.Token, time.Minute, func(_ context.Context, req wire.Request) wire.Reply {
		return wire.Reply{OK: req.Operation == "good", Data: req.Data}
	}, recorder.record)
	if err != nil {
		t.Fatal(err)
	}
	defer keeper.Close()
	wrong := auth
	wrong.Token = strings.Repeat("9", 64)
	if _, err := Connect(context.Background(), keeper.Endpoint(), keeper.Pin(), wrong); !errors.Is(err, ErrRejected) {
		t.Fatalf("wrong token = %v", err)
	}
	client, err := Connect(context.Background(), keeper.Endpoint(), keeper.Pin(), auth)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.CallRaw(context.Background(), "good", map[string]string{"secret": "request-data"}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CallRaw(context.Background(), "bad", nil); err == nil {
		t.Fatal("refused operation succeeded")
	}
	var failures traceRecorder
	client.SetTrace(failures.record)
	client.Close()
	select {
	case <-keeper.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("keeper outlived its attached connection")
	}
	keeper.Close()
	if _, err := client.CallRaw(context.Background(), "good", nil); err == nil {
		t.Fatal("call on a closed client succeeded")
	}
	if got := failures.find("call-failed "); !strings.HasPrefix(got, "call-failed op good stage write cause ") {
		t.Fatalf("client failure trace = %q", got)
	}
	if _, err := Connect(context.Background(), keeper.Endpoint(), keeper.Pin(), auth); !errors.Is(err, ErrDial) {
		t.Fatalf("re-attach after shutdown = %v", err)
	}
	for _, want := range []string{
		"listen ttl_ms 60000",
		"connection-end attached false stage claim cause credentials requests 0 ",
		"attached ",
		"request op good ok true ",
		"request op bad ok false ",
		"connection-end attached true stage request-read cause eof requests 2 ",
		"shutdown reason attached-connection-ended",
	} {
		if recorder.find(want) == "" {
			t.Fatalf("trace lacks %q in %q", want, recorder.events)
		}
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	shutdowns := 0
	for _, event := range recorder.events {
		if strings.HasPrefix(event, "shutdown ") {
			shutdowns++
		}
		if strings.Contains(event, "request-data") || strings.Contains(event, auth.Token) || strings.Contains(event, auth.Session) {
			t.Fatalf("trace carried request data or a credential: %q", event)
		}
	}
	if shutdowns != 1 {
		t.Fatalf("shutdown was traced %d times", shutdowns)
	}
}

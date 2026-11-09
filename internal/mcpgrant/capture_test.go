package mcpgrant

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
)

// grantRecord builds one schema-valid captured record through a real directory
// so identifiers, revisions and validation match production records.
func grantRecord(t *testing.T, endpoint, kind, username string, secret []byte, headers ...mcpdirectory.Header) (Record, mcpdirectory.Binding) {
	t.Helper()
	directory := mcpdirectory.New()
	t.Cleanup(directory.Clear)
	server, err := directory.AddServer("fixed", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	account := mcpdirectory.Account{ServerID: server, Name: "account", Enabled: true, Auth: mcpdirectory.Authentication{Kind: kind, Username: username, Secret: secret}, Headers: headers}
	id, err := directory.AddAccount(account)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := directory.CurrentBinding(id)
	if err != nil {
		t.Fatal(err)
	}
	return Record{ServerID: binding.ServerID, AccountID: id, Server: directory.Servers[server], Account: directory.Accounts[id]}, binding
}

func grantContext(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestNewCaptureOwnsCapturedCredentialsIndependentlyOfCallerBuffers(t *testing.T) {
	record, binding := grantRecord(t, "https://mcp.example.org/mcp", "bearer", "", []byte("synthetic-private-auth"))
	ctx := grantContext(t)
	capture, err := NewCapture(ctx, "synthetic", 3, [32]byte{7}, []Record{record})
	if err != nil || capture == nil {
		t.Fatal("schema-valid capture was refused")
	}
	// Mutate the caller-side copies after admission: an owned capture must be
	// unaffected by buffer clearing and later directory-shaped edits.
	clear(record.Account.Auth.Secret)
	record.Account.Auth.Secret = nil
	record.Server.Revision++
	record.Server.Enabled = false
	launch, err := capture.Issue(ctx, "synthetic", 3, []mcpdirectory.Binding{binding})
	if err != nil || launch == nil {
		t.Fatal("owned capture lost the credential after caller buffer mutation")
	}
	snapshot, err := launch.Guard()
	if err != nil || snapshot == nil {
		t.Fatal("launch refused its output guard")
	}
	var output bytes.Buffer
	writer, err := outputguard.NewWriter(snapshot, &output)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []byte("synthetic-private-auth") {
		if _, err := writer.Write([]byte{value}); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil || output.String() != outputguard.Marker {
		t.Fatal("capture guard lost the owned credential literal")
	}
	capture.Close(ctx)
	if err := launch.Close(ctx); err != nil {
		t.Fatal("launch cleanup failed")
	}
}

func TestNewCaptureRefusesInvalidOrUnownedRecordSets(t *testing.T) {
	base, _ := grantRecord(t, "https://mcp.example.org/mcp", "bearer", "", []byte("synthetic-private-auth"))
	oversized := make([]Record, 0, 17)
	for index := 0; index < 17; index++ {
		record, _ := grantRecord(t, "https://mcp.example.org/mcp", "bearer", "", []byte("synthetic-private-auth"))
		oversized = append(oversized, record)
	}
	a, _ := grantRecord(t, "https://mcp.example.org/mcp", "bearer", "", []byte("synthetic-private-auth"))
	b, _ := grantRecord(t, "https://mcp.example.org/mcp", "bearer", "", []byte("synthetic-private-auth"))
	ctx := grantContext(t)
	b.ServerID = a.ServerID
	b.Account.ServerID = a.ServerID
	b.Server.Revision = a.Server.Revision + 1
	cases := []struct {
		name    string
		profile string
		digest  [32]byte
		records []Record
	}{
		{"empty-profile", "", [32]byte{7}, []Record{base}},
		{"oversized-profile", strings.Repeat("x", 65), [32]byte{7}, []Record{base}},
		{"zero-digest", "synthetic", [32]byte{}, []Record{base}},
		{"nil-records", "synthetic", [32]byte{7}, nil},
		{"empty-records", "synthetic", [32]byte{7}, []Record{}},
		{"oversized-selection", "synthetic", [32]byte{7}, oversized},
		{"duplicate-account", "synthetic", [32]byte{7}, []Record{base, {ServerID: base.ServerID, AccountID: base.AccountID, Server: base.Server, Account: base.Account}}},
		{"conflicting-server", "synthetic", [32]byte{7}, []Record{a, b}},
	}
	mutated := []struct {
		name   string
		change func(*Record)
	}{
		{"disabled-account", func(r *Record) { r.Account.Enabled = false }},
		{"disabled-server", func(r *Record) { r.Server.Enabled = false }},
		{"account-server-mismatch", func(r *Record) { r.Account.ServerID = "other" }},
		{"zero-server-revision", func(r *Record) { r.Server.Revision = 0 }},
		{"empty-endpoint", func(r *Record) { r.Server.URL = "" }},
		{"invalid-auth-kind", func(r *Record) { r.Account.Auth.Kind = "oauth" }},
		{"empty-account-id", func(r *Record) { r.AccountID = "" }},
		{"oversized-account-id", func(r *Record) { r.AccountID = strings.Repeat("x", 65) }},
	}
	for _, test := range mutated {
		record := base
		test.change(&record)
		cases = append(cases, struct {
			name    string
			profile string
			digest  [32]byte
			records []Record
		}{test.name, "synthetic", [32]byte{7}, []Record{record}})
	}
	for _, test := range cases {
		capture, err := NewCapture(ctx, test.profile, 3, test.digest, test.records)
		if capture != nil || err != ErrGrant {
			t.Fatalf("case %s: invalid record set was admitted", test.name)
		}
	}
	bounded := make([]Record, 0, 16)
	for index := 0; index < 16; index++ {
		record, _ := grantRecord(t, "https://mcp.example.org/mcp", "bearer", "", []byte("synthetic-private-auth"))
		bounded = append(bounded, record)
	}
	capture, err := NewCapture(ctx, "synthetic", 3, [32]byte{7}, bounded)
	if err != nil || capture == nil {
		t.Fatal("full bounded selection was refused")
	}
	capture.Close(ctx)
}

func TestCaptureIssuePreflightRefusalsDoNotConsumeTheCapture(t *testing.T) {
	recordA, bindingA := grantRecord(t, "https://mcp.example.org/mcp", "bearer", "", []byte("synthetic-a"))
	recordB, bindingB := grantRecord(t, "https://mcp.example.org/mcp", "basic", "owner", []byte("synthetic-b"))
	ctx := grantContext(t)
	capture, err := NewCapture(ctx, "synthetic", 3, [32]byte{7}, []Record{recordA, recordB})
	if err != nil || capture == nil {
		t.Fatal("valid capture was refused")
	}
	ctx = grantContext(t)
	staleServer := bindingA
	staleServer.ServerRevision++
	staleAccount := bindingA
	staleAccount.AccountRevision++
	swapped := bindingB
	swapped.ServerID = bindingA.ServerID
	oversized := append([]mcpdirectory.Binding{}, bindingA, bindingB)
	for index := 0; index < 15; index++ {
		oversized = append(oversized, bindingA)
	}
	refusals := []struct {
		name     string
		profile  string
		revision uint64
		bindings []mcpdirectory.Binding
	}{
		{"wrong-profile", "other", 3, []mcpdirectory.Binding{bindingA}},
		{"wrong-revision", "synthetic", 4, []mcpdirectory.Binding{bindingA}},
		{"nil-bindings", "synthetic", 3, nil},
		{"empty-bindings", "synthetic", 3, []mcpdirectory.Binding{}},
		{"duplicate", "synthetic", 3, []mcpdirectory.Binding{bindingA, bindingA}},
		{"unknown-account", "synthetic", 3, []mcpdirectory.Binding{{ServerID: bindingA.ServerID, AccountID: "unknown", ServerRevision: 1, AccountRevision: 1}}},
		{"stale-server", "synthetic", 3, []mcpdirectory.Binding{staleServer}},
		{"stale-account", "synthetic", 3, []mcpdirectory.Binding{staleAccount}},
		{"swapped-server", "synthetic", 3, []mcpdirectory.Binding{swapped}},
		{"oversized", "synthetic", 3, oversized},
	}
	for _, test := range refusals {
		launch, err := capture.Issue(ctx, test.profile, test.revision, test.bindings)
		if launch != nil || err != ErrGrant {
			t.Fatalf("case %s: preflight mismatch was admitted", test.name)
		}
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if launch, err := capture.Issue(cancelled, "synthetic", 3, []mcpdirectory.Binding{bindingA}); launch != nil || err != ErrGrant {
		t.Fatal("cancelled context was admitted")
	}
	if launch, err := capture.Issue(nil, "synthetic", 3, []mcpdirectory.Binding{bindingA}); launch != nil || err != ErrGrant {
		t.Fatal("nil context was admitted")
	}
	var missing *Capture
	if launch, err := missing.Issue(ctx, "synthetic", 3, []mcpdirectory.Binding{bindingA}); launch != nil || err != ErrGrant {
		t.Fatal("nil capture was admitted")
	}
	launch, err := capture.Issue(ctx, "synthetic", 3, []mcpdirectory.Binding{bindingA, bindingB})
	if err != nil || launch == nil {
		t.Fatal("preflight refusals consumed the capture")
	}
	if err := launch.Close(ctx); err != nil {
		t.Fatal("launch cleanup failed")
	}
	capture.Close(ctx)
	if launch, err := capture.Issue(ctx, "synthetic", 3, []mcpdirectory.Binding{bindingA, bindingB}); launch != nil || err != ErrGrant {
		t.Fatal("closed capture was reused")
	}
}

package broker

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/enrollment"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

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
		{Protocol: FullProtocol, Mode: ModeFull, Complete: true, Tools: []string{"remote_targets", "remote_exec", "remote_read", "remote_cancel", "app_list", "app_exec", "app_read", "app_cancel"}, SnapshotDigest: strings.Repeat("a", 64)},
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

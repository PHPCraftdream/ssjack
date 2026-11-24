package core

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/canonicaljson"
	"github.com/PHPCraftdream/ssjack/internal/keyfile"
	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/mcpgrant"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
	"github.com/PHPCraftdream/ssjack/internal/sshproxy"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/approval"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/record"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/store"
	"github.com/ktav-lang/golang/pure"
)

func testTarget(t *testing.T) Target {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	block, err := ssh.MarshalPrivateKey(private, "test")
	if err != nil {
		t.Fatal(err)
	}
	public, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	return Target{Address: "example.test:22", User: "test", PrivateKey: pem.EncodeToMemory(block), HostKeys: []string{string(ssh.MarshalAuthorizedKey(public))}}
}

func TestVaultPayloadRoundTripAndCleanup(t *testing.T) {
	for _, populated := range []bool{false, true} {
		v := New()
		if populated {
			v.Targets["test"] = testTarget(t)
		}
		encoded, err := Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := Unmarshal(encoded)
		if err != nil {
			t.Fatal(err)
		}
		if decoded.Version != 1 || len(decoded.Targets) != len(v.Targets) ||
			!bytes.Equal(decoded.Targets["test"].PrivateKey, v.Targets["test"].PrivateKey) {
			t.Fatal("vault payload changed")
		}
		private := decoded.Targets["test"].PrivateKey
		decoded.Close()
		if len(decoded.Targets) != 0 || !bytes.Equal(private, make([]byte, len(private))) {
			t.Fatal("private key buffers were not cleared")
		}
		v.Close()
	}
}

func TestVaultStrictFieldsAndValidation(t *testing.T) {
	v := New()
	v.Targets["test"] = testTarget(t)
	defer v.Close()
	encoded, err := Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	for _, extra := range []string{"\nunknown: true\n", "\ntargets.test.unknown: true\n", "\nversion: 1\n"} {
		if loaded, err := Unmarshal(append(append([]byte(nil), encoded...), []byte(extra)...)); err == nil {
			loaded.Close()
			t.Fatal("unknown or duplicate fields were accepted")
		}
	}
	for _, name := range []string{"", "-name", "a b", "../name", strings.Repeat("x", 65), "name\n"} {
		if err := record.ValidateName(name); err == nil {
			t.Fatal("invalid target name was accepted")
		}
	}
	for _, mutate := range []func(*Target){
		func(v *Target) { v.Address = "missing-port" },
		func(v *Target) { v.Address = ":22" },
		func(v *Target) { v.User = "" },
		func(v *Target) { v.PrivateKey = []byte("invalid") },
		func(v *Target) { v.HostKeys = nil },
		func(v *Target) { v.HostKeys = []string{"invalid"} },
		func(v *Target) { v.HostKeys = []string{v.HostKeys[0], v.HostKeys[0]} },
	} {
		changed := v.Targets["test"]
		mutate(&changed)
		if err := changed.Validate(); err == nil {
			t.Fatal("invalid target credentials were accepted")
		}
	}
}

func TestImportedKeyPreservesMetadataAndOwnsBytes(t *testing.T) {
	v := New()
	defer v.Close()
	original := testTarget(t)
	v.Targets["selected"] = original
	oldBytes := append([]byte(nil), original.PrivateKey...)
	defer clear(oldBytes)
	if err := v.ReplaceKey("selected", []byte("invalid")); err == nil {
		t.Fatal("invalid replacement was accepted")
	}
	if !bytes.Equal(v.Targets["selected"].PrivateKey, oldBytes) {
		t.Fatal("invalid import changed the old key")
	}
	incoming := testTarget(t)
	if err := v.ReplaceKey("selected", incoming.PrivateKey); err != nil {
		t.Fatal(err)
	}
	want := append([]byte(nil), incoming.PrivateKey...)
	defer clear(want)
	clear(incoming.PrivateKey)
	got := v.Targets["selected"]
	if got.Address != original.Address || got.User != original.User || len(got.HostKeys) != len(original.HostKeys) || got.HostKeys[0] != original.HostKeys[0] {
		t.Fatal("key import changed connection metadata or server pins")
	}
	if !bytes.Equal(got.PrivateKey, want) || !bytes.Equal(original.PrivateKey, make([]byte, len(original.PrivateKey))) {
		t.Fatal("replacement key ownership or old-key clearing failed")
	}
	if err := v.ReplaceKey("missing", want); err == nil {
		t.Fatal("key-only import created an incomplete credential record")
	}
}

func TestVaultLockAndSizeLimits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault")
	if err := os.WriteFile(path+".lock", nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(path, []byte("opaque encrypted document"), nil); err == nil {
		t.Fatal("vault lock was ignored")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("locked vault was created")
	}
	if _, err := os.Stat(path + ".lock"); err != nil {
		t.Fatal("another writer's lock was removed")
	}
	if _, err := Unmarshal(make([]byte, 64*1024+1)); err == nil {
		t.Fatal("oversized plaintext vault was accepted")
	}
	if _, err := store.ReadEncoded(filepath.Dir(path)); err == nil {
		t.Fatal("directory was accepted as an encrypted vault")
	}
}

func TestServerPinReplacementPreservesCredentials(t *testing.T) {
	v := New()
	defer v.Close()
	original := testTarget(t)
	original.Usage = "human"
	v.Targets["home"] = original
	if err := v.ReplaceHostKeys("home", []string{"invalid"}); err == nil {
		t.Fatal("invalid server key was accepted")
	}
	other := testTarget(t)
	defer clear(other.PrivateKey)
	pins := append([]string(nil), other.HostKeys...)
	if err := v.ReplaceHostKeys("home", pins); err != nil {
		t.Fatal(err)
	}
	pins[0] = "caller mutation"
	updated := v.Targets["home"]
	if updated.Address != original.Address || updated.User != original.User || updated.Usage != original.Usage || !bytes.Equal(updated.PrivateKey, original.PrivateKey) {
		t.Fatal("host pin replacement changed credential identity or usage")
	}
	if updated.HostKeys[0] != other.HostKeys[0] {
		t.Fatal("host pin replacement did not own its input")
	}
	if err := v.ReplaceHostKeys("missing", other.HostKeys); err == nil {
		t.Fatal("host pin replacement created an incomplete record")
	}
}

func TestUsageCompatibilityAndGates(t *testing.T) {
	for _, usage := range []string{"", "both", "human", "agent"} {
		target := testTarget(t)
		target.Usage = usage
		v := New()
		v.Targets["record"] = target
		encoded, err := Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if usage == "" && strings.Contains(string(encoded), "usage:") {
			t.Fatal("legacy record acquired an implicit policy field")
		}
		decoded, err := Unmarshal(encoded)
		if err != nil {
			t.Fatal(err)
		}
		for _, mode := range []string{"human", "agent"} {
			err := decoded.Targets["record"].RequireUsage(mode)
			allowed := usage == "" || usage == "both" || usage == mode
			if (err == nil) != allowed {
				t.Fatalf("usage=%q mode=%q error=%v", usage, mode, err)
			}
		}
		decoded.Close()
		v.Close()
	}
	target := testTarget(t)
	defer clear(target.PrivateKey)
	target.Usage = "readonly"
	if err := target.Validate(); err == nil {
		t.Fatal("unsupported client-side readonly policy was accepted")
	}
	if err := target.RequireUsage("unknown"); err == nil {
		t.Fatal("unknown caller mode was accepted")
	}
}

func TestEncryptedSSHPolicyRoundTripAndSafeApplication(t *testing.T) {
	safe := ssh.SupportedAlgorithms()
	v := New()
	defer v.Close()
	target := testTarget(t)
	v.Targets["main"] = target
	policy := SSHPolicy{HostKeys: safe.HostKeys[:1], KeyExchanges: safe.KeyExchanges[:1], Ciphers: safe.Ciphers[:1], MACs: safe.MACs[:1]}
	if err := v.ReplacePolicy("main", policy); err != nil {
		t.Fatal(err)
	}
	encoded, err := Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Unmarshal(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer decoded.Close()
	got := decoded.Targets["main"]
	if !reflect.DeepEqual(got.SSHPolicy, policy) {
		t.Fatal("algorithm policy changed during encrypted-payload serialization")
	}
	config, err := got.ClientConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(config.Ciphers, policy.Ciphers) || !reflect.DeepEqual(config.HostKeyAlgorithms, policy.HostKeys) || config.HostKeyCallback == nil {
		t.Fatal("policy was ignored or disabled server trust")
	}
	defaultConfig, err := target.ClientConfig()
	if err != nil || !reflect.DeepEqual(defaultConfig.Ciphers, safe.Ciphers) {
		t.Fatal("default policy did not use supported safe algorithms")
	}
}

func TestUnsafeUnknownAndDuplicatePoliciesRejected(t *testing.T) {
	for _, policy := range []SSHPolicy{
		{Ciphers: []string{"none"}},
		{Ciphers: []string{"unknown-cipher"}},
		{MACs: []string{"not-a-supported-mac"}},
		{KeyExchanges: []string{"diffie-hellman-group1-sha1"}},
		{Ciphers: []string{ssh.SupportedAlgorithms().Ciphers[0], ssh.SupportedAlgorithms().Ciphers[0]}},
	} {
		if err := policy.Validate(); err == nil {
			t.Fatal("unsafe or duplicate policy was accepted")
		}
	}
}

func TestPasswordIdentityNormalizesVerifiedHostKeys(t *testing.T) {
	target := testTarget(t)
	defer clear(target.PrivateKey)
	if !strings.HasSuffix(target.HostKeys[0], "\n") {
		t.Fatal("fixture does not exercise a valid newline-terminated OpenSSH key")
	}
	first, err := passwordIdentityMetadata("selected", target)
	if err != nil {
		t.Fatal("valid OpenSSH host key could not form password identity metadata")
	}
	if _, err := canonicaljson.Canonicalize(first); err != nil {
		t.Fatal("password identity metadata is not canonicalizable")
	}
	target.HostKeys = []string{strings.TrimSpace(target.HostKeys[0])}
	second, err := passwordIdentityMetadata("selected", target)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("OpenSSH text newline changed the verified host identity")
	}
	target.User = "another-user"
	changed, err := passwordIdentityMetadata("selected", target)
	if err != nil || bytes.Equal(first, changed) {
		t.Fatal("selected SSH username was not bound")
	}
	target.HostKeys = []string{"invalid"}
	if _, err := passwordIdentityMetadata("selected", target); err == nil {
		t.Fatal("invalid host key produced password identity metadata")
	}
}

func TestPasswordClientConfigOutlivesVaultBuffers(t *testing.T) {
	v, server := directoryFixture(t)
	target := v.Targets["production"]
	signer, err := ssh.ParsePrivateKey(target.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	target.PrivateKey, target.Password = nil, []byte("synthetic-owned-password")
	defer clear(target.Password)
	if err := v.SetAccount(server, "password", target); err != nil {
		t.Fatal(err)
	}
	profile, err := v.AccountProfile(server, "password")
	if err != nil {
		t.Fatal(err)
	}
	config, err := v.Targets[profile].ClientConfig()
	if err != nil {
		t.Fatal(err)
	}
	v.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	release, result, finished := make(chan struct{}), make(chan error, 1), make(chan struct{})
	defer func() {
		listener.Close()
		close(release)
		<-finished
	}()
	serverConfig := &ssh.ServerConfig{PasswordCallback: func(metadata ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		if metadata.User() != target.User || subtle.ConstantTimeCompare(password, target.Password) != 1 {
			return nil, errors.New("synthetic credential mismatch")
		}
		return nil, nil
	}}
	serverConfig.AddHostKey(signer)
	go func() {
		defer close(finished)
		connection, err := listener.Accept()
		if err != nil {
			result <- err
			return
		}
		defer connection.Close()
		if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			result <- err
			return
		}
		sshConnection, _, _, err := ssh.NewServerConn(connection, serverConfig)
		result <- err
		if err == nil {
			defer sshConnection.Close()
			<-release
		}
	}()
	config.Timeout = 5 * time.Second
	client, err := ssh.Dial("tcp", listener.Addr().String(), config)
	if err != nil {
		t.Fatal("password authentication failed after vault cleanup")
	}
	defer client.Close()
	if err := <-result; err != nil {
		t.Fatal("synthetic SSH server rejected the selected password")
	}
}

func TestSnapshotRejectsRevisionChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault")
	data := []byte("authenticated ciphertext fixture")
	if err := store.Commit(path, data, nil); err != nil {
		t.Fatal(err)
	}
	v := New()
	defer v.Close()
	v.revision = sha256.Sum256(data)
	backup, err := Snapshot(path, v)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(backup); err != nil || !bytes.Equal(got, data) {
		t.Fatal("snapshot bytes changed")
	}
	if err := os.WriteFile(path, []byte("newer revision"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Snapshot(path, v); err == nil {
		t.Fatal("unauthenticated newer revision was snapshotted")
	}
}

func TestVaultCachedRekeyFullProfile(t *testing.T) {
	if os.Getenv("SSJACK_TEST_FULL_KDF") != "1" {
		t.Skip("production KDF runs only in GitHub CI")
	}
	path := filepath.Join(t.TempDir(), "rekey")
	password, replacement := []byte("old fixture secret"), []byte("new fixture secret")
	if err := Create(path, password); err != nil {
		t.Fatal(err)
	}
	v, err := Load(path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	old := v.unlocked
	if err := SaveContext(context.Background(), path, v, replacement); err != nil {
		t.Fatal(err)
	}
	if _, err := old.Seal([]byte("late old-key write")); err == nil {
		t.Fatal("successful rekey retained old master")
	}
	v.Targets["main"] = testTarget(t)
	if err := SaveUnlocked(context.Background(), path, v); err != nil {
		t.Fatal(err)
	}
	reopened, err := Load(path, replacement)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if len(reopened.Targets) != 1 {
		t.Fatal("cached post-rekey write lost data")
	}
	if stale, err := Load(path, password); err == nil {
		stale.Close()
		t.Fatal("cached write reverted the vault secret")
	}
	owned := v.unlocked
	v.Close()
	if _, err := owned.Seal([]byte("after close")); err == nil {
		t.Fatal("vault Close retained master")
	}
}

func TestVaultGeneratedProfileFullProfile(t *testing.T) {
	if os.Getenv("SSJACK_TEST_FULL_KDF") != "1" {
		t.Skip("production KDF runs only in GitHub CI")
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "generated.ssjack.ktav")
	password := []byte("production generated profile fixture")
	v, err := NewUnlocked(password)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	public, private, err := v.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	target := testTarget(t)
	clear(target.PrivateKey)
	target.PrivateKey = append([]byte(nil), private...)
	defer clear(target.PrivateKey)
	owned := v.unlocked
	if err := v.InitializeDirectory("generated", target); err != nil {
		t.Fatal(err)
	}
	if v.unlocked != owned {
		t.Fatal("directory initialization replaced the retained encryption context")
	}
	if err := CreateUnlocked(context.Background(), path, v); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 || entries[0].Name() != "generated.ssjack.ktav" {
		t.Fatal("generation wrote extra key or public files")
	}
	reopened, err := Load(path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	server, err := reopened.ServerID("generated")
	if err != nil {
		t.Fatal(err)
	}
	profile, err := reopened.AccountProfile(server, "main")
	if err != nil || profile != "generated" || reopened.Version != 2 {
		t.Fatal("generated database did not retain directory schema and profile selection")
	}
	got, err := keyfile.PublicSSH(reopened.Targets["generated"].PrivateKey)
	if err != nil || !bytes.Equal(got, public) {
		t.Fatal("stored generated identity changed")
	}
	encoded, err := store.ReadEncoded(path)
	if err != nil || bytes.Contains(encoded, private) || bytes.Contains(encoded, public) {
		t.Fatal("key material appeared outside encryption")
	}
}

func TestVaultProxyFullProfile(t *testing.T) {
	if os.Getenv("SSJACK_TEST_FULL_KDF") != "1" {
		t.Skip("production KDF runs only in dedicated GitHub CI")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	v, server, first := proxyFixture(t)
	route := &sshproxy.Config{Type: sshproxy.SOCKS5, Address: "proxy.invalid:1080", Username: "operator", Password: []byte("synthetic proxy password")}
	defer route.Clear()
	if err := v.SetServerProxy(server, route); err != nil {
		t.Fatal(err)
	}
	password := []byte("synthetic proxy database password")
	defer clear(password)
	path := filepath.Join(t.TempDir(), "proxied.ktav")
	if err := CreateWithRecords(ctx, path, v, password); err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(path)
	if err != nil || bytes.Contains(encoded, route.Password) {
		t.Fatal("proxy credentials were not encrypted")
	}
	loaded, err := Load(path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Close()
	if !sshproxy.Equal(route, loaded.Targets[first].Proxy) {
		t.Fatal("encrypted database lost proxy settings")
	}
	baseline := make(map[string]string)
	for _, profile := range loaded.Servers[server].Accounts {
		binding, err := loaded.ProxyCredentialIdentity(profile)
		if err != nil || len(binding) != 64 {
			t.Fatal("authenticated proxy binding unavailable")
		}
		baseline[profile] = binding
	}
	for _, mutate := range []func(*sshproxy.Config){
		func(c *sshproxy.Config) { c.Type = sshproxy.HTTP },
		func(c *sshproxy.Config) { c.Address = "changed.invalid:1080" },
		func(c *sshproxy.Config) { c.Username = "changed" },
		func(c *sshproxy.Config) { clear(c.Password); c.Password = []byte("changed synthetic proxy password") },
	} {
		changed := sshproxy.Clone(route)
		mutate(changed)
		if err := loaded.SetServerProxy(server, changed); err != nil {
			t.Fatal(err)
		}
		changed.Clear()
		for _, profile := range loaded.Servers[server].Accounts {
			binding, err := loaded.ProxyCredentialIdentity(profile)
			if err != nil || binding == baseline[profile] {
				t.Fatal("grant binding ignored a changed server route or proxy authentication")
			}
		}
	}
	if err := loaded.SetServerProxy(server, route); err != nil {
		t.Fatal(err)
	}
	if err := SaveUnlocked(ctx, path, loaded); err != nil {
		t.Fatal(err)
	}
	reopened, err := Load(path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	for _, profile := range reopened.Servers[server].Accounts {
		binding, err := reopened.ProxyCredentialIdentity(profile)
		if err != nil || binding != baseline[profile] {
			t.Fatal("normal encrypted save changed the route grant binding")
		}
		if len(reopened.Targets[profile].Password) != 0 {
			selected, err := reopened.PasswordCredentialIdentity(profile)
			if err != nil || selected != binding {
				t.Fatal("password grant binding omitted its proxy route")
			}
		}
	}
	if err := reopened.SetServerProxy(server, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.ProxyCredentialIdentity(first); err == nil {
		t.Fatal("direct credential was treated as a proxied grant")
	}
}

func TestLegacyGuardRefusesUnauthenticatedOrDirectoryState(t *testing.T) {
	for _, state := range []*Vault{nil, New(), NewDirectory()} {
		if snapshot, err := state.LegacyOutputGuard(context.Background(), "missing"); snapshot != nil || err != outputguard.ErrGuard {
			t.Fatal("unauthenticated legacy or directory state granted a capability")
		}
	}
	if snapshot, err := New().LegacyOutputGuard(nil, "missing"); snapshot != nil || err != outputguard.ErrGuard {
		t.Fatal("legacy capture accepted a missing context")
	}
}

func TestCredentialGuardCapturesBothPendingRotationKeys(t *testing.T) {
	state := NewDirectory()
	state.Targets["active"] = Target{PrivateKey: []byte("synthetic-active-key")}
	state.Rotation = &RotationJournal{
		Phase:      RotationPrepared,
		Original:   Target{PrivateKey: []byte("synthetic-retained-old-key")},
		NewPrivate: []byte("synthetic-pending-new-key"),
	}
	snapshot, err := CredentialGuard(state)
	if err != nil {
		t.Fatal(err)
	}
	state.Close()
	var result bytes.Buffer
	writer, err := outputguard.NewWriter(snapshot, &result)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("synthetic-active-key|synthetic-retained-old-key|synthetic-pending-new-key")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if result.String() != "[REDACTED]|[REDACTED]|[REDACTED]" {
		t.Fatal("pending rotation credential was not masked after vault buffers were cleared")
	}
}

func TestCredentialGuardCapturesOldKeyAfterCommitAndNotArchivedArtifact(t *testing.T) {
	state := NewDirectory()
	state.Targets["active"] = Target{PrivateKey: []byte("synthetic-current-new-key")}
	state.Rotation = &RotationJournal{
		Phase:      RotationComplete,
		Original:   Target{PrivateKey: []byte("synthetic-retained-old-key")},
		NewPrivate: []byte("synthetic-current-new-key"),
	}
	snapshot, err := CredentialGuard(state)
	if err != nil {
		t.Fatal(err)
	}
	state.Close()
	var result bytes.Buffer
	writer, err := outputguard.NewWriter(snapshot, &result)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("synthetic-retained-old-key|synthetic-current-new-key|synthetic-archived-only-key")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if result.String() != "[REDACTED]|[REDACTED]|synthetic-archived-only-key" {
		t.Fatal("completed journal keys or archive boundary were not handled as expected")
	}
}

func TestCredentialGuardRefusesWholeOversizedCredentialSet(t *testing.T) {
	state := New()
	state.Targets["large"] = Target{PrivateKey: make([]byte, outputguard.MaxPatternSize+1)}
	if snapshot, err := CredentialGuard(state); snapshot != nil || err != outputguard.ErrGuard {
		t.Fatal("oversized credential was truncated or omitted")
	}
	state.Targets = nil
	state.RemoteMCP = mcpdirectory.New()
	account := mcpdirectory.Account{}
	for range outputguard.MaxPatterns + 1 {
		account.Headers = append(account.Headers, mcpdirectory.Header{Value: []byte("synthetic")})
	}
	state.RemoteMCP.Accounts["many"] = account
	if snapshot, err := CredentialGuard(state); snapshot != nil || err != outputguard.ErrGuard {
		t.Fatal("credential count overflow was truncated")
	}
}

func TestRotationPhasePredicates(t *testing.T) {
	active := map[string]bool{
		RotationPrepared: true, RotationAttempting: true, RotationUnknown: true,
		RotationAdded: true, RotationVerified: true, RotationCommitted: true,
	}
	verification := map[string]bool{RotationAttempting: true, RotationUnknown: true, RotationAdded: true}
	phases := []string{
		RotationPrepared, RotationAttempting, RotationUnknown, RotationAdded, RotationVerified,
		RotationCommitted, RotationComplete, RotationCancelled, RotationArchived, "", "bogus",
	}
	for _, phase := range phases {
		if got := LiveRotationPhase(phase); got != active[phase] {
			t.Errorf("LiveRotationPhase(%q) = %v, want %v", phase, got, active[phase])
		}
		if got := RotationAwaitsVerification(phase); got != verification[phase] {
			t.Errorf("RotationAwaitsVerification(%q) = %v, want %v", phase, got, verification[phase])
		}
	}
}

func remoteFixture(t *testing.T) (*Vault, string, string) {
	t.Helper()
	v, ssh := directoryFixture(t)
	v.RemoteMCP = mcpdirectory.New()
	server, err := v.RemoteMCP.AddServer("docs", "https://docs.invalid/mcp")
	if err != nil {
		t.Fatal(err)
	}
	account, err := v.RemoteMCP.AddAccount(mcpdirectory.Account{ServerID: server, Name: "work", Enabled: true, Auth: mcpdirectory.Authentication{Kind: "bearer", Secret: []byte("synthetic-private-MCP-token")}})
	if err != nil {
		t.Fatal(err)
	}
	return v, ssh, account
}

func TestRemoteMCPOldPayloadAndUnknownFieldsRefuseLoss(t *testing.T) {
	old, _ := directoryFixture(t)
	encoded, err := Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Unmarshal(encoded)
	clear(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer decoded.Close()
	if decoded.RemoteMCP != nil {
		t.Fatal("old database gained MCP state implicitly")
	}
	v, _, _ := remoteFixture(t)
	encoded, err = Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	raw, err := pure.LoadsStrict(string(encoded))
	if err != nil {
		t.Fatal(err)
	}
	root := raw.(map[string]any)
	remote := root["remote_mcp"].(map[string]any)
	remote["unknown"] = true
	bad, err := pure.EmitCanonical(root)
	if err != nil {
		t.Fatal(err)
	}
	if loaded, err := Unmarshal([]byte(bad)); err == nil {
		loaded.Close()
		t.Fatal("unknown MCP field was silently discarded")
	}
	v.RemoteMCP.Last["missing-profile"] = []mcpdirectory.Binding{}
	if _, err := Marshal(v); err == nil {
		t.Fatal("MCP preference accepted an unknown SSH context")
	}
}

// The pre-adoption production entry must refuse a vault that is not in an
// authenticated unchanged state; the real ciphertext path is covered by the
// full-profile suite.
func TestVaultRemoteMCPCaptureRefusesUnauthenticatedState(t *testing.T) {
	v, server := directoryFixture(t)
	profile, err := v.AccountProfile(server, "main")
	if err != nil {
		t.Fatal(err)
	}
	v.RemoteMCP = mcpdirectory.New()
	remote, err := v.RemoteMCP.AddServer("remote", "https://capture.example.org/mcp")
	if err != nil {
		t.Fatal(err)
	}
	keyed, err := v.RemoteMCP.AddAccount(mcpdirectory.Account{ServerID: remote, Name: "keyed", Enabled: true, Auth: mcpdirectory.Authentication{Kind: "bearer", Secret: []byte("synthetic-vault-capture")}})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := v.RemoteMCP.CurrentBinding(keyed)
	if err != nil {
		t.Fatal(err)
	}
	ctx := sessionTestContext(t)
	digest := [32]byte{6}
	if capture, err := v.RemoteMCPCapture(ctx, "unused", digest, profile, []mcpdirectory.Binding{binding}); capture != nil || err != mcpgrant.ErrGrant {
		t.Fatal("unauthenticated vault granted a capture")
	}
	var nilVault *Vault
	if capture, err := nilVault.RemoteMCPCapture(ctx, "unused", digest, profile, []mcpdirectory.Binding{binding}); capture != nil || err != mcpgrant.ErrGrant {
		t.Fatal("nil vault was accepted")
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if capture, err := v.RemoteMCPCapture(cancelled, "unused", digest, profile, []mcpdirectory.Binding{binding}); capture != nil || err != mcpgrant.ErrGrant {
		t.Fatal("cancelled context was accepted")
	}
}

// A file replaced while the capture is being assembled must revoke the newly
// owned copies at the return boundary instead of reaching the caller. The
// mutate seam of the unexported admission core makes that window deterministic
// without sleeps, global hooks or a second KDF.
func TestVaultRemoteMCPCaptureRefusesMidConstructionOriginChange(t *testing.T) {
	v, server := directoryFixture(t)
	profile, err := v.AccountProfile(server, "main")
	if err != nil {
		t.Fatal(err)
	}
	// Forge an authenticated unchanged vault without any KDF, exactly like the
	// private handoff-guard tests.
	v.unlocked = new(keyfile.Unlocked)
	v.RemoteMCP = mcpdirectory.New()
	remote, err := v.RemoteMCP.AddServer("remote", "https://capture.example.org/mcp")
	if err != nil {
		t.Fatal(err)
	}
	keyed, err := v.RemoteMCP.AddAccount(mcpdirectory.Account{ServerID: remote, Name: "keyed", Enabled: true, Auth: mcpdirectory.Authentication{Kind: "bearer", Secret: []byte("synthetic-mid-construction")}})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := v.RemoteMCP.CurrentBinding(keyed)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	v.payloadHash = sha256.Sum256(payload)
	clear(payload)
	encoded := []byte("authenticated ciphertext under test")
	digest := sha256.Sum256(encoded)
	v.revision = digest
	path := filepath.Join(t.TempDir(), "vault")
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	ctx := sessionTestContext(t)
	replaced := false
	capture, err := v.remoteMCPCapture(ctx, path, digest, profile, []mcpdirectory.Binding{binding}, func() {
		replaced = true
		if err := os.WriteFile(path, []byte("replaced during construction"), 0600); err != nil {
			t.Fatal(err)
		}
	})
	if !replaced || capture != nil || err != mcpgrant.ErrGrant {
		t.Fatal("mid-construction origin change was not refused")
	}
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	clean, err := v.remoteMCPCapture(ctx, path, digest, profile, []mcpdirectory.Binding{binding}, nil)
	if err != nil || clean == nil {
		t.Fatal("restored origin did not admit a capture")
	}
	if err := clean.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func sessionTestContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// Test seams for the external core_test package.

func FormatOf(v *Vault) int { return v.format }

func RevisionOf(v *Vault) [sha256.Size]byte { return v.revision }

// ForgeAuthenticated marks v as authenticated and unchanged without any KDF.
func ForgeAuthenticated(t *testing.T, v *Vault) {
	t.Helper()
	v.unlocked = new(keyfile.Unlocked)
	payload, err := Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	v.payloadHash = sha256.Sum256(payload)
	clear(payload)
}

func ForgeRevision(v *Vault, revision [sha256.Size]byte) { v.revision = revision }
func approvalRecord(t *testing.T, name string) approval.Record {
	t.Helper()
	return approval.Record{Name: name, Path: filepath.Join(t.TempDir(), name), Hash: strings.Repeat("ab", 32)}
}

// The copy seam is unexported, so this lifecycle subtest stays in the core
// package; every assertion otherwise goes through the exported API, reading
// the live set via ListApplicationApprovals instead of the raw map.
func TestVaultApplicationApprovalCopyKeepsIndependentApprovals(t *testing.T) {
	v, _ := directoryFixture(t)
	rec := approvalRecord(t, "tool")
	if err := v.ApproveApplication(rec, ""); err != nil {
		t.Fatal(err)
	}
	if err := v.InitializeDirectory("again", record.OwnTarget(v.Targets["production"])); err == nil {
		t.Fatal("initialization was accepted on a vault with approvals")
	}
	copy, err := v.directoryCopy()
	if err != nil {
		t.Fatal(err)
	}
	copy.Approvals["extra"] = approvalRecord(t, "extra")
	if list, err := v.ListApplicationApprovals(); err != nil || len(list) != 1 {
		t.Fatal("mutating the copy changed the original approval set")
	}
	target := record.OwnTarget(v.Targets["production"])
	defer clear(target.PrivateKey)
	if _, err := v.AddServer("another", "main", target); err != nil {
		t.Fatal(err)
	}
	if list, err := v.ListApplicationApprovals(); err != nil || len(list) != 1 || list[0] != rec {
		t.Fatal("directory edit lost the approval set")
	}
}

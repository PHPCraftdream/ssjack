// Package core holds the vault data model, its wire codec, validation and encrypted-file lifecycle.
package core

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/canonicaljson"
	"github.com/PHPCraftdream/ssjack/internal/keyfile"
	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/record"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/store"
)

type (
	Target        = record.Target
	SSHPolicy     = record.SSHPolicy
	Server        = record.Server
	SecretBinding = record.SecretBinding
)

type Vault struct {
	Version     int                      `json:"version"`
	Targets     map[string]Target        `json:"targets"`
	Servers     map[string]Server        `json:"servers,omitempty"`
	Secrets     map[string]SecretBinding `json:"secrets,omitempty"`
	OwnerStore  *OwnerStore              `json:"owner_store,omitempty"`
	RemoteMCP   *mcpdirectory.Directory  `json:"remote_mcp,omitempty"`
	Rotation    *RotationJournal         `json:"rotation,omitempty"`
	revision    [sha256.Size]byte
	payloadHash [sha256.Size]byte
	format      int
	unlocked    *keyfile.Unlocked
	writer      *store.Role
}

func New() *Vault {
	return &Vault{Version: 1, Targets: make(map[string]Target)}
}

func (v *Vault) Close() {
	v.unlocked.Close()
	v.unlocked = nil
	for name, target := range v.Targets {
		clear(target.PrivateKey)
		clear(target.Password)
		target.Proxy.Clear()
		delete(v.Targets, name)
	}
	clear(v.Servers)
	clear(v.Secrets)
	v.OwnerStore.clear()
	v.OwnerStore = nil
	v.RemoteMCP.Clear()
	v.RemoteMCP = nil
	if v.Rotation != nil {
		ClearJournal(v.Rotation)
	}
	v.Rotation = nil
	clear(v.payloadHash[:])
	v.writer.Close()
}

func (v *Vault) ReplaceKey(name string, private []byte) error {
	target, exists := v.Targets[name]
	if !exists {
		return errors.New("credential record does not exist")
	}
	if len(private) == 0 || len(private) > keyfile.MaxPlaintext {
		return errors.New("invalid imported private key size")
	}
	updated := target
	updated.Password = nil
	updated.PrivateKey = append([]byte(nil), private...)
	if err := updated.Validate(); err != nil {
		clear(updated.PrivateKey)
		return err
	}
	clear(target.PrivateKey)
	clear(target.Password)
	v.Targets[name] = updated
	return nil
}

func (v *Vault) ReplaceHostKeys(name string, pins []string) error {
	target, exists := v.Targets[name]
	if !exists {
		return errors.New("credential record does not exist")
	}
	updated := target
	updated.HostKeys = append([]string(nil), pins...)
	if err := updated.Validate(); err != nil {
		return err
	}
	v.Targets[name] = updated
	return nil
}

func (v *Vault) validate() error {
	if (v.Version != 1 && v.Version != 2) || v.Targets == nil || len(v.Targets) > 64 {
		return errors.New("unsupported vault version or target count")
	}
	if v.Version == 1 && (v.Servers != nil || v.Secrets != nil || v.OwnerStore != nil || v.RemoteMCP != nil || v.Rotation != nil) {
		return errors.New("version 1 cannot contain directory metadata")
	}
	if v.Version == 2 {
		if err := v.validateDirectory(); err != nil {
			return err
		}
		if err := v.validateOwnerStore(); err != nil {
			return err
		}
		if err := v.validateRemoteMCP(); err != nil {
			return err
		}
		if err := ValidateRotation(v); err != nil {
			return err
		}
	}
	for name, target := range v.Targets {
		if v.Version == 1 && len(target.Password) != 0 {
			return errors.New("password authentication requires database version 2")
		}
		if v.Version == 1 && target.Proxy != nil {
			return errors.New("proxy settings require database version 2")
		}
		if err := record.ValidateName(name); err != nil {
			return err
		}
		if err := target.Validate(); err != nil {
			return fmt.Errorf("invalid target %q: %w", name, err)
		}
	}
	return nil
}

func (v *Vault) ReplacePolicy(name string, policy SSHPolicy) error {
	target, ok := v.Targets[name]
	if !ok {
		return errors.New("profile does not exist")
	}
	if err := policy.Validate(); err != nil {
		return err
	}
	target.SSHPolicy = SSHPolicy{
		HostKeys:     append([]string(nil), policy.HostKeys...),
		KeyExchanges: append([]string(nil), policy.KeyExchanges...),
		Ciphers:      append([]string(nil), policy.Ciphers...),
		MACs:         append([]string(nil), policy.MACs...),
	}
	v.Targets[name] = target
	return nil
}

func Load(path string, password []byte) (*Vault, error) {
	encoded, err := store.ReadEncoded(path)
	if err != nil {
		return nil, err
	}
	plaintext, unlocked, err := keyfile.Unlock(encoded, password)
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)
	v, err := Unmarshal(plaintext)
	if err != nil {
		unlocked.Close()
		return nil, err
	}
	canonical, err := Marshal(v)
	if err != nil {
		unlocked.Close()
		v.Close()
		return nil, err
	}
	v.payloadHash = sha256.Sum256(canonical)
	clear(canonical)
	v.unlocked = unlocked
	v.revision = sha256.Sum256(encoded)
	v.format, err = keyfile.Format(encoded)
	if err != nil {
		v.Close()
		return nil, err
	}
	return v, nil
}

// NewUnlocked prepares one master for generation and initial database storage.
func NewUnlocked(password []byte) (*Vault, error) {
	unlocked, err := keyfile.NewUnlocked(password, 2)
	if err != nil {
		return nil, err
	}
	v := New()
	v.unlocked = unlocked
	v.format = 2
	return v, nil
}

func (v *Vault) GenerateIdentity() ([]byte, []byte, error) {
	if v.unlocked == nil {
		return nil, nil, errors.New("vault has no unlocked encryption context")
	}
	return v.unlocked.GenerateIdentity()
}

func CreateUnlocked(ctx context.Context, path string, v *Vault) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if v.unlocked == nil {
		return errors.New("vault has no unlocked encryption context")
	}
	plaintext, err := Marshal(v)
	if err != nil {
		return err
	}
	defer clear(plaintext)
	encoded, err := v.unlocked.Seal(plaintext)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := store.Commit(path, encoded, nil); err != nil {
		return err
	}
	v.revision = sha256.Sum256(encoded)
	v.payloadHash = sha256.Sum256(plaintext)
	return nil
}

func Create(path string, password []byte) error {
	return CreateContext(context.Background(), path, password)
}

func CreateContext(ctx context.Context, path string, password []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	v := New()
	defer v.Close()
	return CreateWithRecords(ctx, path, v, password)
}

func CreateWithRecords(ctx context.Context, path string, v *Vault, password []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	plaintext, err := Marshal(v)
	if err != nil {
		return err
	}
	defer clear(plaintext)
	encoded, err := keyfile.Seal(plaintext, password)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return store.Commit(path, encoded, nil)
}

func Save(path string, v *Vault, password []byte) error {
	return SaveContext(context.Background(), path, v, password)
}

func SaveContext(ctx context.Context, path string, v *Vault, password []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	plaintext, err := Marshal(v)
	if err != nil {
		return err
	}
	defer clear(plaintext)
	unlocked, err := keyfile.NewUnlocked(password, v.format)
	if err != nil {
		return err
	}
	retained := false
	defer func() {
		if !retained {
			unlocked.Close()
		}
	}()
	encoded, err := unlocked.Seal(plaintext)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := store.CommitWithRole(path, encoded, &v.revision, v.writer); err != nil {
		return err
	}
	v.revision = sha256.Sum256(encoded)
	v.payloadHash = sha256.Sum256(plaintext)
	v.unlocked.Close()
	v.unlocked = unlocked
	retained = true
	return nil
}

// SaveUnlocked uses only the master retained by Load, never the password again.
func SaveUnlocked(ctx context.Context, path string, v *Vault) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if v.unlocked == nil {
		return errors.New("vault has no unlocked encryption context")
	}
	plaintext, err := Marshal(v)
	if err != nil {
		return err
	}
	defer clear(plaintext)
	encoded, err := v.unlocked.Seal(plaintext)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := store.CommitWithRole(path, encoded, &v.revision, v.writer); err != nil {
		return err
	}
	v.revision = sha256.Sum256(encoded)
	v.payloadHash = sha256.Sum256(plaintext)
	return nil
}

// ClaimWriter pins an authenticated unchanged database before owner effects.
func (v *Vault) ClaimWriter(path string) error {
	if v == nil || v.unlocked == nil || v.revision == ([sha256.Size]byte{}) {
		return store.ErrWriterRole
	}
	if v.writer != nil {
		return v.writer.Write(path, func(canonical string) error {
			encoded, err := store.ReadEncoded(canonical)
			if err != nil || sha256.Sum256(encoded) != v.revision {
				return store.ErrWriterRole
			}
			return nil
		})
	}
	role, err := store.ClaimRole(path)
	if err != nil {
		return err
	}
	encoded, err := store.ReadEncoded(role.Path())
	if err != nil || sha256.Sum256(encoded) != v.revision {
		role.Close()
		return store.ErrWriterRole
	}
	v.writer = role
	return nil
}

// VerifyAdoption proves an authenticated unchanged vault before session adoption.
func VerifyAdoption(ctx context.Context, path string, v *Vault) error {
	if ctx == nil {
		return errors.New("database session requires a context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if v.Version != 2 {
		return errors.New("migrate the database before opening the directory editor")
	}
	return verifyVaultCapture(ctx, path, v)
}

func verifyVaultCapture(ctx context.Context, path string, v *Vault) error {
	if v.unlocked == nil || v.payloadHash == ([sha256.Size]byte{}) {
		return errors.New("database session requires an authenticated unchanged vault")
	}
	payload, err := Marshal(v)
	if err != nil {
		return err
	}
	matches := sha256.Sum256(payload) == v.payloadHash
	clear(payload)
	if !matches {
		return errors.New("vault was edited before session adoption")
	}
	encoded, err := store.ReadEncoded(path)
	if err != nil {
		return err
	}
	if sha256.Sum256(encoded) != v.revision {
		return errors.New("vault changed before session adoption")
	}
	return ctx.Err()
}

// Handoff gives the unlock context and writer role to a session; v keeps neither.
func Handoff(v *Vault) (*keyfile.Unlocked, [sha256.Size]byte, *store.Role) {
	key, revision, role := v.unlocked, v.revision, v.writer
	v.unlocked, v.writer = nil, nil
	return key, revision, role
}

// DetachReadOnlyKey gives the unlock of a version 2 vault without a writer role
// to an owner helper; it returns nil otherwise and leaves v unchanged.
func DetachReadOnlyKey(v *Vault) *keyfile.Unlocked {
	if v.Version != 2 || v.unlocked == nil || v.writer != nil {
		return nil
	}
	key := v.unlocked
	v.unlocked = nil
	return key
}

// Snapshot preserves the revision previously authenticated by Load.
func Snapshot(path string, v *Vault) (string, error) {
	encoded, err := store.ReadEncoded(path)
	if err != nil {
		return "", err
	}
	if sha256.Sum256(encoded) != v.revision {
		return "", errors.New("vault changed before recovery snapshot; reload it first")
	}
	backup, err := store.RecoveryPath(path, "snapshot")
	if err != nil {
		return "", err
	}
	if err := store.Commit(backup, encoded, nil); err != nil {
		return "", err
	}
	return backup, nil
}

// ProxyCredentialIdentity never publishes an unkeyed proxy-password verifier.
func (v *Vault) ProxyCredentialIdentity(profile string) (string, error) {
	if err := v.validate(); err != nil {
		return "", err
	}
	target, exists := v.Targets[profile]
	if !exists || target.Proxy == nil {
		return "", errors.New("selected proxied credential does not exist")
	}
	pins := make([]string, 0, len(target.HostKeys))
	for _, encoded := range target.HostKeys {
		key, err := record.ParseHostKey([]byte(encoded))
		if err != nil {
			return "", errors.New("invalid selected SSH identity")
		}
		pins = append(pins, ssh.FingerprintSHA256(key))
	}
	sort.Strings(pins)
	kind, signer := "password", ""
	if len(target.Password) == 0 {
		key, err := ssh.ParsePrivateKey(target.PrivateKey)
		if err != nil {
			return "", errors.New("invalid selected SSH identity")
		}
		kind, signer = "key", ssh.FingerprintSHA256(key.PublicKey())
	}
	raw, err := json.Marshal(map[string]any{
		"format": "ssjack-ssh-proxy-identity-v1", "profile": profile,
		"address": target.Address, "user": target.User, "host_keys": pins,
		"authentication": kind, "signer": signer, "proxy_type": target.Proxy.Type,
		"proxy_address": target.Proxy.Address, "proxy_user": target.Proxy.Username,
	})
	if err != nil {
		return "", errors.New("cannot encode routed credential identity")
	}
	identity, err := canonicaljson.Canonicalize(raw)
	if err != nil {
		return "", errors.New("cannot canonicalize routed credential identity")
	}
	private := make([]byte, 0, 16+len(target.Password)+len(target.Proxy.Password))
	private = binary.BigEndian.AppendUint64(private, uint64(len(target.Password)))
	private = append(private, target.Password...)
	private = binary.BigEndian.AppendUint64(private, uint64(len(target.Proxy.Password)))
	private = append(private, target.Proxy.Password...)
	defer clear(private)
	binding, err := v.unlocked.SSHProxyBinding(identity, private)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(binding[:]), nil
}

// PasswordCredentialIdentity binds exact selected credentials without publishing
// an offline password verifier. It requires the authenticated owner unlock.
func (v *Vault) PasswordCredentialIdentity(profile string) (string, error) {
	if err := v.validate(); err != nil {
		return "", err
	}
	target, exists := v.Targets[profile]
	if !exists || len(target.Password) == 0 {
		return "", errors.New("selected password credential does not exist")
	}
	if target.Proxy != nil {
		return v.ProxyCredentialIdentity(profile)
	}
	canonical, err := passwordIdentityMetadata(profile, target)
	if err != nil {
		return "", err
	}
	binding, err := v.unlocked.SSHPasswordBinding(canonical, target.Password)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(binding[:]), nil
}

func passwordIdentityMetadata(profile string, target Target) ([]byte, error) {
	pins := make([]string, len(target.HostKeys))
	for i, encoded := range target.HostKeys {
		key, err := record.ParseHostKey([]byte(encoded))
		if err != nil {
			return nil, err
		}
		pins[i] = ssh.FingerprintSHA256(key)
	}
	sort.Strings(pins)
	identity := struct {
		Profile        string   `json:"profile"`
		Address        string   `json:"address"`
		User           string   `json:"user"`
		HostKeys       []string `json:"host_keys"`
		Authentication string   `json:"authentication"`
	}{profile, target.Address, target.User, pins, "password"}
	raw, err := json.Marshal(identity)
	if err != nil {
		return nil, errors.New("cannot encode password credential identity")
	}
	canonical, err := canonicaljson.Canonicalize(raw)
	if err != nil {
		return nil, errors.New("cannot canonicalize password credential identity")
	}
	return canonical, nil
}

// Validate checks the vault's schema, bounds and cross-record invariants.
func Validate(v *Vault) error { return v.validate() }

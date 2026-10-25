package remote

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"

	"github.com/ktav-lang/golang/pure"
	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/sshauth"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/PHPCraftdream/ssjack/internal/keyfile"
)

type Target struct {
	Address    string `json:"address"`
	User       string `json:"user"`
	Key        string `json:"key"`
	KnownHosts string `json:"known_hosts"`
}

type Config struct {
	Keys    map[string]string `json:"keys"`
	Targets map[string]Target `json:"targets"`
}

func LoadConfig(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 64*1024+1))
	if err != nil || len(data) > 64*1024 {
		return Config{}, errors.New("invalid Ktav configuration size")
	}
	parsed, err := pure.LoadsStrict(string(data))
	if err != nil {
		return Config{}, errors.New("invalid Ktav configuration")
	}
	root, ok := parsed.(map[string]any)
	if !ok || checkKeys(root, "keys", "targets") != nil {
		return Config{}, errors.New("configuration must contain only keys and targets")
	}
	keys, ok := root["keys"].(map[string]any)
	if !ok || len(keys) == 0 || len(keys) > 16 {
		return Config{}, errors.New("configuration must define 1 to 16 keys")
	}
	for _, value := range keys {
		if _, ok := value.(string); !ok {
			return Config{}, errors.New("key paths must be strings")
		}
	}
	targets, ok := root["targets"].(map[string]any)
	if !ok || len(targets) == 0 || len(targets) > 64 {
		return Config{}, errors.New("configuration must define 1 to 64 targets")
	}
	for _, value := range targets {
		target, ok := value.(map[string]any)
		if !ok || checkKeys(target, "address", "user", "key", "known_hosts") != nil {
			return Config{}, errors.New("each target must contain only address, user, key, and known_hosts")
		}
	}
	var config Config
	if err := pure.LoadsInto(string(data), &config); err != nil {
		return Config{}, errors.New("failed to decode Ktav configuration")
	}
	base, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return Config{}, err
	}
	for name, key := range config.Keys {
		if name == "" || key == "" {
			return Config{}, errors.New("key names and paths must not be empty")
		}
		if !filepath.IsAbs(key) {
			config.Keys[name] = filepath.Join(base, key)
		}
	}
	for name, target := range config.Targets {
		if name == "" || target.User == "" || target.KnownHosts == "" || config.Keys[target.Key] == "" {
			return Config{}, errors.New("each target requires a name, user, key, and known_hosts")
		}
		if _, _, err := net.SplitHostPort(target.Address); err != nil {
			return Config{}, errors.New("target address must use host:port form")
		}
		if !filepath.IsAbs(target.KnownHosts) {
			target.KnownHosts = filepath.Join(base, target.KnownHosts)
		}
		config.Targets[name] = target
	}
	return config, nil
}

func checkKeys(values map[string]any, allowed ...string) error {
	set := make(map[string]bool, len(allowed))
	for _, key := range allowed {
		set[key] = true
	}
	for key := range values {
		if !set[key] {
			return fmt.Errorf("unknown field %q", key)
		}
	}
	return nil
}

func Unlock(config Config, passphrase []byte) (map[string]ssh.Signer, error) {
	if len(passphrase) == 0 {
		return nil, errors.New("empty passphrases are not allowed")
	}
	signers := make(map[string]ssh.Signer)
	for name, path := range config.Keys {
		file, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("failed to open SSH key %q", name)
		}
		data, readErr := io.ReadAll(io.LimitReader(file, 1024*1024+1))
		file.Close()
		if readErr != nil || len(data) > 1024*1024 {
			clear(data)
			return nil, fmt.Errorf("failed to read SSH key %q", name)
		}
		signer, err := unlockKey(data, passphrase)
		clear(data)
		if err != nil {
			return nil, fmt.Errorf("failed to unlock SSH key %q", name)
		}
		signers[name] = signer
	}
	return signers, nil
}

func unlockKey(data, passphrase []byte) (ssh.Signer, error) {
	if keyfile.IsContainer(data) {
		plaintext, err := keyfile.Open(data, passphrase)
		if err != nil {
			return nil, err
		}
		defer clear(plaintext)
		return ssh.ParsePrivateKey(plaintext)
	}
	_, err := ssh.ParseRawPrivateKey(data)
	var missing *ssh.PassphraseMissingError
	if !errors.As(err, &missing) {
		return nil, errors.New("SSH key must be encrypted in a supported format")
	}
	return ssh.ParsePrivateKeyWithPassphrase(data, passphrase)
}

func NewSSHRunner(config Config, signers map[string]ssh.Signer) (Runner, error) {
	type connection struct {
		target Target
		config *ssh.ClientConfig
	}
	connections := make(map[string]connection)
	for name, target := range config.Targets {
		signer := signers[target.Key]
		if signer == nil {
			return nil, errors.New("unlocked SSH key not found")
		}
		callback, err := knownhosts.New(target.KnownHosts)
		if err != nil {
			return nil, fmt.Errorf("failed to read known_hosts for %q", name)
		}
		connections[name] = connection{target, &ssh.ClientConfig{
			User: target.User, Auth: []ssh.AuthMethod{sshauth.PublicKey(signer)}, HostKeyCallback: callback,
		}}
	}
	return func(ctx context.Context, target, command string, stdout, stderr io.Writer) (int, error) {
		entry, ok := connections[target]
		if !ok {
			return -1, errors.New("target is not allowed")
		}
		return runSSH(ctx, entry.target.Address, entry.config, command, stdout, stderr)
	}, nil
}

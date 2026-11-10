package sshlive

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/outputguard"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/sshstatus"
)

var ErrUnavailable = errors.New("SSH live capability unavailable")

type Material struct {
	Profile  string
	Scope    string
	Revision uint64
	Config   *ssh.ClientConfig
	Address  string
	Guard    *outputguard.Snapshot
}

type Source func(context.Context) (Material, error)

type Status = sshstatus.Status

type Runtime struct {
	mu      sync.Mutex
	source  Source
	profile string
	scope   string
	address string
	user    string
	status  Status
}

func New(ctx context.Context, profile string, source Source) (*Runtime, error) {
	if ctx == nil || ctx.Err() != nil || profile == "" || source == nil {
		return nil, ErrUnavailable
	}
	material, err := source(ctx)
	if err != nil || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	config, ok := cloneConfig(material.Config)
	if !ok || material.Profile != profile || material.Scope == "" || material.Address == "" || material.Guard == nil {
		return nil, ErrUnavailable
	}
	return &Runtime{
		source: source, profile: profile, scope: material.Scope, address: material.Address, user: config.User,
		status: Status{Profile: profile, DesiredRevision: material.Revision, DesiredKnown: true},
	}, nil
}

func cloneConfig(config *ssh.ClientConfig) (*ssh.ClientConfig, bool) {
	if config == nil || config.User == "" || config.HostKeyCallback == nil || len(config.Auth) == 0 {
		return nil, false
	}
	copy := *config
	copy.Auth = append([]ssh.AuthMethod(nil), config.Auth...)
	copy.HostKeyAlgorithms = append([]string(nil), config.HostKeyAlgorithms...)
	copy.KeyExchanges = append([]string(nil), config.KeyExchanges...)
	copy.Ciphers = append([]string(nil), config.Ciphers...)
	copy.MACs = append([]string(nil), config.MACs...)
	return &copy, true
}

func (r *Runtime) Admit(ctx context.Context, target, command string) (remote.AdmittedOperation, error) {
	if r == nil || ctx == nil || ctx.Err() != nil || target != r.profile {
		return remote.AdmittedOperation{}, ErrUnavailable
	}
	material, err := r.source(ctx)
	if err != nil || ctx.Err() != nil {
		r.setUnavailable()
		return remote.AdmittedOperation{}, ErrUnavailable
	}
	config, ok := cloneConfig(material.Config)
	if !ok || material.Profile != r.profile || material.Scope != r.scope || material.Address != r.address || material.Config.User != r.user || config.User != r.user || material.Guard == nil {
		r.setUnavailable()
		return remote.AdmittedOperation{}, ErrUnavailable
	}
	var issued atomic.Bool
	var issueOnce sync.Once
	ack := func() {
		r.mu.Lock()
		if issued.Load() && (!r.status.AdoptedKnown || material.Revision > r.status.AdoptedRevision) {
			r.status.AdoptedRevision, r.status.AdoptedKnown = material.Revision, true
		}
		r.mu.Unlock()
	}
	runner, err := remote.NewAcknowledgedCredentialRunner(r.profile, r.address, config, ack)
	if err != nil || ctx.Err() != nil {
		r.setUnavailable()
		return remote.AdmittedOperation{}, ErrUnavailable
	}
	r.mu.Lock()
	if r.status.DesiredKnown && material.Revision < r.status.DesiredRevision {
		r.status.Unavailable = true
		r.mu.Unlock()
		return remote.AdmittedOperation{}, ErrUnavailable
	}
	if !r.status.DesiredKnown || material.Revision > r.status.DesiredRevision {
		r.status.DesiredRevision, r.status.DesiredKnown = material.Revision, true
	}
	r.status.Unavailable = false
	r.mu.Unlock()
	return remote.AdmittedOperation{
		Runner: runner, Guard: material.Guard,
		Issued: func() {
			issueOnce.Do(func() {
				r.mu.Lock()
				if !r.status.DeliveredKnown || material.Revision > r.status.DeliveredRevision {
					r.status.DeliveredRevision, r.status.DeliveredKnown = material.Revision, true
				}
				issued.Store(true)
				r.mu.Unlock()
			})
		},
	}, nil
}

func (r *Runtime) setUnavailable() {
	r.mu.Lock()
	r.status.Unavailable = true
	r.mu.Unlock()
}

func (r *Runtime) Status() Status {
	if r == nil {
		return Status{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.status
}

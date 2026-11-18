package remote

import (
	"context"

	"golang.org/x/crypto/ssh"

	jobs "github.com/PHPCraftdream/ssjack/internal/remote/internal/jobs"
	transport "github.com/PHPCraftdream/ssjack/internal/remote/internal/transport"
)

type (
	Runner            = jobs.Runner
	StreamRunner      = transport.StreamRunner
	StartInput        = jobs.StartInput
	StartOutput       = jobs.StartOutput
	ReadInput         = jobs.ReadInput
	ReadOutput        = jobs.ReadOutput
	JobInput          = jobs.JobInput
	TargetsOutput     = jobs.TargetsOutput
	CancelOutput      = jobs.CancelOutput
	Manager           = jobs.Manager
	GuardProvider     = jobs.GuardProvider
	AdmissionProvider = jobs.AdmissionProvider
	AdmittedOperation = jobs.AdmittedOperation
	WindowSize        = transport.WindowSize
	ShellOptions      = transport.ShellOptions
	Target            = transport.Target
	Config            = transport.Config
)

var (
	ErrJob              = jobs.ErrJob
	ErrAdmission        = jobs.ErrAdmission
	ErrInputNotReleased = transport.ErrInputNotReleased
)

func NewManager(parent context.Context, targets []string, runner Runner) *Manager {
	return jobs.NewManager(parent, targets, runner)
}

func NewAdmittedManager(parent context.Context, targets []string, provider AdmissionProvider) *Manager {
	return jobs.NewAdmittedManager(parent, targets, provider)
}

func NewGuardedManager(parent context.Context, targets []string, runner Runner, provider GuardProvider) *Manager {
	return jobs.NewGuardedManager(parent, targets, runner, provider)
}

func NewCredentialRunner(name, address string, config *ssh.ClientConfig) (Runner, error) {
	return transport.NewCredentialRunner(name, address, config)
}

func NewCredentialStreamRunner(name, address string, config *ssh.ClientConfig) (StreamRunner, error) {
	return transport.NewCredentialStreamRunner(name, address, config)
}

func NewAcknowledgedCredentialRunner(name, address string, config *ssh.ClientConfig, acknowledge func()) (Runner, error) {
	return transport.NewAcknowledgedCredentialRunner(name, address, config, acknowledge)
}

func NewSSHRunner(config Config, signers map[string]ssh.Signer) (Runner, error) {
	return transport.NewSSHRunner(config, signers)
}

func LoadConfig(path string) (Config, error) {
	return transport.LoadConfig(path)
}

func Unlock(config Config, passphrase []byte) (map[string]ssh.Signer, error) {
	return transport.Unlock(config, passphrase)
}

func Check(ctx context.Context, address string, config *ssh.ClientConfig) error {
	return transport.Check(ctx, address, config)
}

func Shell(ctx context.Context, opts ShellOptions) (int, error) {
	return transport.Shell(ctx, opts)
}

func PreflightAdd(config *ssh.ClientConfig, oldPublic, newPublic []byte) error {
	return transport.PreflightAdd(config, oldPublic, newPublic)
}

func AddAuthorizedKey(ctx context.Context, address string, config *ssh.ClientConfig, oldPublic, newPublic []byte) error {
	return transport.AddAuthorizedKey(ctx, address, config, oldPublic, newPublic)
}

func RetireAuthorizedKey(ctx context.Context, address string, config *ssh.ClientConfig, oldPublic, newPublic []byte) error {
	return transport.RetireAuthorizedKey(ctx, address, config, oldPublic, newPublic)
}

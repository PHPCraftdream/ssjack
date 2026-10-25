package sshauth

import (
	"errors"
	"io"
	"sync/atomic"

	"golang.org/x/crypto/ssh"
)

type publicKeyAuth struct {
	ssh.AuthMethod
	signer ssh.Signer
}

// PublicKey identifies the single selected signer without exposing key material.
func PublicKey(signer ssh.Signer) ssh.AuthMethod {
	return &publicKeyAuth{AuthMethod: ssh.PublicKeys(signer), signer: signer}
}

// ForConnection creates fresh signing evidence; it is never reused across dials.
func ForConnection(config *ssh.ClientConfig) (*ssh.ClientConfig, func() bool, error) {
	if config == nil || len(config.Auth) != 1 {
		return nil, nil, errors.New("SSH requires exactly one selected public-key identity")
	}
	method, ok := config.Auth[0].(*publicKeyAuth)
	if !ok || method == nil || method.signer == nil {
		return nil, nil, errors.New("SSH configuration lacks identifiable selected-key authentication")
	}
	var signed atomic.Bool
	copy := *config
	copy.Auth = []ssh.AuthMethod{ssh.PublicKeys(trackSigner(method.signer, &signed))}
	return &copy, signed.Load, nil
}

type trackedSigner struct {
	ssh.Signer
	signed *atomic.Bool
}

func (s trackedSigner) Sign(random io.Reader, data []byte) (*ssh.Signature, error) {
	signature, err := s.Signer.Sign(random, data)
	if err == nil {
		s.signed.Store(true)
	}
	return signature, err
}

type trackedAlgorithmSigner struct {
	trackedSigner
	algorithm ssh.AlgorithmSigner
}

func (s trackedAlgorithmSigner) SignWithAlgorithm(random io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	signature, err := s.algorithm.SignWithAlgorithm(random, data, algorithm)
	if err == nil {
		s.signed.Store(true)
	}
	return signature, err
}

type trackedMultiAlgorithmSigner struct {
	trackedAlgorithmSigner
	multi ssh.MultiAlgorithmSigner
}

func (s trackedMultiAlgorithmSigner) Algorithms() []string {
	return append([]string(nil), s.multi.Algorithms()...)
}

func trackSigner(signer ssh.Signer, signed *atomic.Bool) ssh.Signer {
	base := trackedSigner{Signer: signer, signed: signed}
	if multi, ok := signer.(ssh.MultiAlgorithmSigner); ok {
		return trackedMultiAlgorithmSigner{
			trackedAlgorithmSigner: trackedAlgorithmSigner{trackedSigner: base, algorithm: multi},
			multi:                  multi,
		}
	}
	if algorithm, ok := signer.(ssh.AlgorithmSigner); ok {
		return trackedAlgorithmSigner{trackedSigner: base, algorithm: algorithm}
	}
	return base
}

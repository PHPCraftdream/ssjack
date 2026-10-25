package sshauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"reflect"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"
)

type basicSigner struct {
	key  ssh.PublicKey
	fail bool
}

func (s *basicSigner) PublicKey() ssh.PublicKey { return s.key }
func (s *basicSigner) Sign(io.Reader, []byte) (*ssh.Signature, error) {
	if s.fail {
		return nil, errors.New("intentional signing error")
	}
	return &ssh.Signature{Format: s.key.Type(), Blob: []byte("signature fixture")}, nil
}

type algorithmSigner struct {
	*basicSigner
	last string
}

func (s *algorithmSigner) SignWithAlgorithm(_ io.Reader, _ []byte, algorithm string) (*ssh.Signature, error) {
	s.last = algorithm
	if s.fail {
		return nil, errors.New("intentional signing error")
	}
	return &ssh.Signature{Format: algorithm, Blob: []byte("signature fixture")}, nil
}

type multiSigner struct{ *algorithmSigner }

func (*multiSigner) Algorithms() []string { return []string{"first", "second"} }

func TestSignerCapabilitiesAndEvidence(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	var signed atomic.Bool
	base := &basicSigner{key: key}
	wrapped := trackSigner(base, &signed)
	if _, ok := wrapped.(ssh.AlgorithmSigner); ok {
		t.Fatal("basic signer gained unsupported algorithm methods")
	}
	wrapped.PublicKey()
	if signed.Load() {
		t.Fatal("a public-key lookup counted as authentication signing")
	}
	base.fail = true
	if _, err := wrapped.Sign(rand.Reader, []byte("challenge")); err == nil || signed.Load() {
		t.Fatal("a failed signature counted as authentication evidence")
	}
	base.fail = false
	if _, err := wrapped.Sign(rand.Reader, []byte("challenge")); err != nil || !signed.Load() {
		t.Fatal("successful signing was not tracked")
	}
	signed.Store(false)
	algorithm := &algorithmSigner{basicSigner: base}
	multi := &multiSigner{algorithmSigner: algorithm}
	tracked := trackSigner(multi, &signed)
	capable, ok := tracked.(ssh.MultiAlgorithmSigner)
	if !ok || !reflect.DeepEqual(capable.Algorithms(), multi.Algorithms()) {
		t.Fatal("multi-algorithm restrictions or preference order were lost")
	}
	if signed.Load() {
		t.Fatal("algorithm capability lookup counted as signing")
	}
	if _, err := capable.SignWithAlgorithm(rand.Reader, []byte("challenge"), "second"); err != nil || !signed.Load() || algorithm.last != "second" {
		t.Fatal("algorithm selection or successful signing evidence was lost")
	}
}

func TestConnectionConfigurationIsIdentifiableAndFresh(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ClientConfig{Auth: []ssh.AuthMethod{PublicKey(signer)}}
	first, proof1, err := ForConnection(config)
	if err != nil {
		t.Fatal(err)
	}
	second, proof2, err := ForConnection(config)
	if err != nil || first == second || first == config || proof1() || proof2() {
		t.Fatal("connection evidence reused configuration or stale signing state")
	}
	if _, _, err := ForConnection(&ssh.ClientConfig{Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}}); err == nil {
		t.Fatal("unidentifiable authentication bypassed the selected-key guard")
	}
}

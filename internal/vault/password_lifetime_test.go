package vault

import (
	"crypto/subtle"
	"errors"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

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

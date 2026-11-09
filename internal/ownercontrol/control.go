// Package ownercontrol selects private owner attach or exclusive standalone control.
package ownercontrol

import (
	"context"
	"errors"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/ownerbackend"
	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/ownerlocal"
	"github.com/PHPCraftdream/ssjack/internal/ownerpacket"
	"github.com/PHPCraftdream/ssjack/internal/ownerrpc"
	"github.com/PHPCraftdream/ssjack/internal/ownerservice"
	"github.com/PHPCraftdream/ssjack/internal/ownertui"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

var ErrControl = errors.New("owner control unavailable; no standalone fallback after occupied, unsafe or unauthenticated endpoint")

type Control struct {
	mu       sync.Mutex
	path     string
	backend  ownertui.Backend
	manager  *ownerdb.Manager
	service  *ownerservice.Service
	unlock   *vault.OwnerUnlock
	client   *ownerrpc.Client
	closed   bool
	closeErr error
}

// Open consumes exactly one database unlock; only a positively absent endpoint
// permits standalone adoption. Authentication/transport failure never falls back.
func Open(ctx context.Context, path string, password []byte) (*Control, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrControl
	}
	loaded, err := vault.Load(path, password)
	if err != nil {
		return nil, ErrControl
	}
	if loaded.Version != 2 {
		loaded.Close()
		return nil, ErrControl
	}
	c := &Control{path: path}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	connection, err := ownerlocal.Dial(bounded, path)
	if err == nil {
		endpoint, identityError := ownerlocal.Identity(path)
		if identityError != nil {
			connection.Close()
			loaded.Close()
			return nil, ErrControl
		}
		c.unlock, err = vault.AdoptOwnerUnlock(loaded, endpoint.Binding)
		if err != nil {
			connection.Close()
			return nil, ErrControl
		}
		peer, err := c.unlock.Peer()
		if err != nil {
			connection.Close()
			c.unlock.Close()
			return nil, ErrControl
		}
		c.client, err = ownerrpc.Attach(bounded, connection, peer)
		if err != nil {
			c.unlock.Close()
			return nil, ErrControl
		}
		remote, err := ownerbackend.NewRemote(ctx, c.client)
		if err != nil {
			c.client.Close()
			c.unlock.Close()
			return nil, ErrControl
		}
		c.backend = remote
		return c, nil
	}
	if connection != nil {
		connection.Close()
	}
	if !errors.Is(err, ownerlocal.ErrAbsent) {
		loaded.Close()
		return nil, ErrControl
	}
	c.manager, err = ownerdb.Adopt(ctx, path, loaded)
	if err != nil {
		return nil, ErrControl
	}
	c.service, err = ownerservice.Start(ctx, c.manager)
	if err != nil {
		cleanup, release := context.WithTimeout(context.Background(), time.Minute)
		defer release()
		c.manager.Close(cleanup)
		return nil, ErrControl
	}
	c.backend = ownerbackend.New(c.manager)
	return c, nil
}

func (c *Control) HumanSSH(ctx context.Context, selected ownertui.Connection) (*ssh.ClientConfig, string, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, "", ErrControl
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, "", ErrControl
	}
	if c.manager != nil {
		return c.manager.HumanSSHAt(selected.Revision, selected.ServerID, selected.Account)
	}
	bounded, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	snapshot, err := c.client.Execute(bounded, ownerpacket.Command{Operation: "flush"})
	if err != nil {
		return nil, "", err
	}
	if snapshot.Status.Database.Revision != selected.Revision || snapshot.Status.Database.SavedRevision != selected.Revision || snapshot.Status.Database.Err != nil || snapshot.CipherDigest == ([32]byte{}) {
		return nil, "", vault.ErrOwnerRevision
	}
	return c.unlock.HumanSSH(c.path, snapshot.CipherDigest, selected.ServerID, selected.Account)
}

func (c *Control) Close(ctx context.Context) error {
	if ctx == nil {
		return ErrControl
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return c.closeErr
	}
	if c.manager != nil {
		serviceError := c.service.Close(ctx)
		select {
		case <-c.service.Done():
		default:
			return ErrControl
		}
		if err := c.manager.Close(ctx); err != nil {
			return err
		}
		c.closed = true
		if serviceError != nil {
			c.closeErr = ErrControl
		}
		return c.closeErr
	}
	if err := c.backend.Flush(ctx); err != nil {
		return err
	}
	c.client.Close()
	c.unlock.Close()
	c.closed = true
	return nil
}

// Detach abandons only this helper connection; a remote keeper remains owned.
func (c *Control) Detach() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client != nil && !c.closed {
		c.client.Close()
		c.unlock.Close()
		c.closed = true
	}
}

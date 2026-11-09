// Package mcpgrant owns private captured remote MCP credentials and fresh
// bounded one-shot launch capabilities. A capture binds owner-confirmed enabled
// records to exact saved-cipher evidence under a finite admission lifetime;
// issuance admits one explicit confirmed choice and never exposes credential
// values.
package mcpgrant

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/mcphttp"
)

// ErrGrant is the fixed sentinel; error values carry no diagnostics.
var ErrGrant = errors.New("remote MCP launch capability unavailable")

const (
	// MaxCaptureLifetime bounds the private admission lifetime of one capture.
	// It is independent of the per-transport exchange lease.
	MaxCaptureLifetime = 10 * time.Minute
	// abortCloseBudget bounds one joined cleanup attempt of retained upstreams.
	abortCloseBudget = 10 * time.Second
)

// Record pairs one captured enabled server with its captured account. Records
// hold owned copies; values never leave the grant layer through getters.
type Record struct {
	ServerID  string
	AccountID string
	Server    mcpdirectory.Server
	Account   mcpdirectory.Account
}

type Capture struct {
	mu       sync.Mutex
	ctx      context.Context
	deadline time.Time
	now      func() time.Time
	profile  string
	revision uint64
	digest   [32]byte
	records  map[string]Record
	doomed   []*mcphttp.Upstream
	issued   bool
	closed   bool
}

// NewCapture privately owns deep copies of the admitted enabled records and
// binds them to one exact saved-state revision, saved-cipher digest, caller
// context and a finite admission lifetime. Caller buffers, later Vault edits,
// adoption and close cannot change or revoke the capture. Construction
// performs no network effect and no unlock or KDF.
func NewCapture(ctx context.Context, profile string, revision uint64, digest [32]byte, records []Record) (*Capture, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrGrant
	}
	if len(profile) == 0 || len(profile) > 64 || digest == ([32]byte{}) {
		return nil, ErrGrant
	}
	if len(records) == 0 || len(records) > mcpdirectory.MaxSelections {
		return nil, ErrGrant
	}
	capture := &Capture{
		ctx:      ctx,
		deadline: time.Now().Add(MaxCaptureLifetime),
		now:      time.Now,
		profile:  profile,
		revision: revision,
		digest:   digest,
		records:  make(map[string]Record, len(records)),
	}
	if err := capture.adopt(records); err != nil {
		return nil, err
	}
	return capture, nil
}

// adopt clones admitted records one by one. A later invalid record clears the
// already owned copies so a failed construction never retains credentials.
func (c *Capture) adopt(records []Record) error {
	servers := make(map[string]mcpdirectory.Server, len(records))
	for _, record := range records {
		if err := admitShape(record); err != nil {
			c.clearRecords()
			return err
		}
		if _, duplicate := c.records[record.AccountID]; duplicate {
			c.clearRecords()
			return ErrGrant
		}
		if previous, seen := servers[record.ServerID]; seen {
			if previous != record.Server {
				c.clearRecords()
				return ErrGrant
			}
		} else {
			servers[record.ServerID] = record.Server
		}
		c.records[record.AccountID] = Record{
			ServerID:  record.ServerID,
			AccountID: record.AccountID,
			Server:    record.Server,
			Account:   ownAccount(record.Account),
		}
	}
	return nil
}

func admitShape(record Record) error {
	if record.ServerID == "" || len(record.ServerID) > 64 || record.AccountID == "" || len(record.AccountID) > 64 {
		return ErrGrant
	}
	if record.Account.ServerID != record.ServerID || record.Server.Revision == 0 || record.Server.URL == "" {
		return ErrGrant
	}
	if !record.Server.Enabled || !record.Account.Enabled || mcpdirectory.ValidateAccount(record.Account) != nil {
		return ErrGrant
	}
	return nil
}

// ownAccount deep-copies credential bytes so caller buffers stay independent.
func ownAccount(account mcpdirectory.Account) mcpdirectory.Account {
	account.Auth.Secret = append([]byte(nil), account.Auth.Secret...)
	if len(account.Headers) != 0 {
		headers := make([]mcpdirectory.Header, len(account.Headers))
		copy(headers, account.Headers)
		for index := range headers {
			headers[index].Value = append([]byte(nil), headers[index].Value...)
		}
		account.Headers = headers
	}
	return account
}

// clearRecords clears owned credential bytes and drops the record references.
func (c *Capture) clearRecords() {
	for _, record := range c.records {
		clear(record.Account.Auth.Secret)
		record.Account.Auth.Secret = nil
		for index := range record.Account.Headers {
			clear(record.Account.Headers[index].Value)
			record.Account.Headers[index].Value = nil
		}
	}
	c.records = nil
}

// Close clears owned credential bytes, permanently refuses later issuance and
// retries the joined shutdown of upstreams retained by an earlier incomplete
// mint cleanup. Incomplete cleanup keeps its ownership and reports ErrGrant;
// a later Close can be waited again with a fresh context.
func (c *Capture) Close(ctx context.Context) error {
	if c == nil {
		return ErrGrant
	}
	if ctx == nil {
		ctx = context.Background()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clearRecords()
	c.closed = true
	kept := make([]*mcphttp.Upstream, 0, len(c.doomed))
	for _, upstream := range c.doomed {
		if upstream.Close(ctx) != nil {
			kept = append(kept, upstream)
		}
	}
	c.doomed = kept
	if len(c.doomed) != 0 {
		return ErrGrant
	}
	return nil
}

package faultproxy

import (
	"context"
	"testing"
	"time"
)

// awaitBudget is the failure timeout of the test helpers; it is never the
// expected wait, only the bound after which a hung test fails.
const awaitBudget = 30 * time.Second

// Start is New for tests: it fails the test on error and closes the proxy
// (joining its goroutines) during cleanup.
func Start(t testing.TB, upstream string, opts ...Option) *Proxy {
	t.Helper()
	p, err := New(upstream, opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// MustSetRules is SetRules that fails the test on an invalid fault.
func (p *Proxy) MustSetRules(t testing.TB, rules ...Rule) {
	t.Helper()
	if err := p.SetRules(rules...); err != nil {
		t.Fatal(err)
	}
}

// Await waits, without sleeping, until the connection with the given index
// exists and is fully released, and returns its final stats. It fails the
// test after a generous budget.
func (p *Proxy) Await(t testing.TB, index int) ConnStats {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), awaitBudget)
	defer cancel()
	c, err := p.WaitConn(ctx, index)
	if err != nil {
		t.Fatalf("connection #%d was never accepted: %v", index, err)
	}
	stats, err := c.Wait(ctx)
	if err != nil {
		t.Fatalf("connection #%d never closed: %v (%+v)", index, err, stats)
	}
	return stats
}

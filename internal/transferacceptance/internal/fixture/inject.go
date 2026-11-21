//go:build linux || darwin

package fixture

import (
	"io"
	"net"
)

// killingStream wraps one direction of the exec channel and closes the whole
// transport once limit bytes crossed it, so a transfer dies mid-stream.
type killingStream struct {
	reader io.Reader
	writer io.Writer
	conn   net.Conn
	limit  int64
	seen   int64
	fired  bool
	onFire func(int64)
}

func (k *killingStream) Read(p []byte) (int, error) {
	n, err := k.reader.Read(p)
	k.cross(int64(n))
	return n, err
}

func (k *killingStream) Write(p []byte) (int, error) {
	n, err := k.writer.Write(p)
	k.cross(int64(n))
	return n, err
}

func (k *killingStream) cross(n int64) {
	if k.fired || n <= 0 {
		return
	}
	k.seen += n
	if k.seen >= k.limit {
		k.fired = true
		_ = k.conn.Close()
		if k.onFire != nil {
			k.onFire(k.seen)
		}
	}
}

// corruptingReader flips one bit at byte offset at of the stream that the
// remote command receives, simulating corruption in flight.
type corruptingReader struct {
	reader  io.Reader
	at      int64
	seen    int64
	flipped bool
	onFire  func(int64)
}

func (c *corruptingReader) Read(p []byte) (int, error) {
	n, err := c.reader.Read(p)
	if n > 0 && !c.flipped && c.seen <= c.at && c.at < c.seen+int64(n) {
		p[c.at-c.seen] ^= 0x01
		c.flipped = true
		if c.onFire != nil {
			c.onFire(c.seen + int64(n))
		}
	}
	c.seen += int64(n)
	return n, err
}

package ownerpacket

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"io"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/keyfile"
)

const domain = "ssjack/owner-ipc/v1"

type box interface {
	Seal([]byte) ([]byte, error)
	Open([]byte) ([]byte, error)
}

type envelope struct {
	Domain    string   `json:"domain"`
	Version   uint8    `json:"version"`
	Kind      string   `json:"kind"`
	Direction string   `json:"direction"`
	Binding   [32]byte `json:"binding"`
	Session   [32]byte `json:"session"`
	Client    [32]byte `json:"client"`
	Sequence  uint64   `json:"sequence"`
	Expires   int64    `json:"expires"`
	Digest    [32]byte `json:"digest"`
	Command   *Command `json:"command,omitempty"`
	Reply     *Reply   `json:"reply,omitempty"`
}

func nonce() ([32]byte, error) {
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil || value == ([32]byte{}) {
		return [32]byte{}, ErrAuthentication
	}
	return value, nil
}

func seal(key box, packet envelope) ([]byte, error) {
	if key == nil {
		return nil, ErrAuthentication
	}
	packet.Domain, packet.Version = domain, 1
	plaintext, err := json.Marshal(packet)
	if err != nil || len(plaintext) == 0 || len(plaintext) > keyfile.MaxPlaintext {
		clear(plaintext)
		return nil, ErrProtocol
	}
	defer clear(plaintext)
	encoded, err := key.Seal(plaintext)
	if err != nil || len(encoded) == 0 || len(encoded) > MaxWire {
		clear(encoded)
		return nil, ErrAuthentication
	}
	return encoded, nil
}

func open(key box, encoded []byte) (packet envelope, err error) {
	if key == nil || len(encoded) == 0 || len(encoded) > MaxWire {
		return packet, ErrAuthentication
	}
	plaintext, err := key.Open(encoded)
	defer clear(plaintext)
	if err != nil {
		return packet, ErrAuthentication
	}
	if len(plaintext) == 0 || len(plaintext) > keyfile.MaxPlaintext {
		return packet, ErrProtocol
	}
	decoder := json.NewDecoder(bytes.NewReader(plaintext))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&packet) != nil {
		packet.clear()
		return envelope{}, ErrProtocol
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		packet.clear()
		return envelope{}, ErrProtocol
	}
	canonical, err := json.Marshal(packet)
	defer clear(canonical)
	if err != nil || !bytes.Equal(canonical, plaintext) || packet.Domain != domain || packet.Version != 1 || packet.Binding == ([32]byte{}) || packet.Session == ([32]byte{}) {
		packet.clear()
		return envelope{}, ErrProtocol
	}
	return packet, nil
}
func (e *envelope) clear() {
	if e.Command != nil {
		e.Command.Clear()
	}
}

type peer struct {
	key                              box
	binding, session, client, digest [32]byte
	expires                          time.Time
	sequence                         uint64
	ready, closed                    bool
	now                              func() time.Time
}

func (p *peer) live() error {
	if p.closed || p.key == nil {
		return ErrAuthentication
	}
	if !p.now().Before(p.expires) {
		p.closed = true
		return ErrExpired
	}
	return nil
}
func (p *peer) matches(packet envelope, kind, direction string, sequence uint64) bool {
	return packet.Kind == kind && packet.Direction == direction && packet.Binding == p.binding && packet.Session == p.session && packet.Client == p.client && packet.Sequence == sequence && packet.Expires == p.expires.Unix() && packet.Digest == p.digest
}
func (p *peer) packet(kind, direction string, sequence uint64) envelope {
	return envelope{Kind: kind, Direction: direction, Binding: p.binding, Session: p.session, Client: p.client, Sequence: sequence, Expires: p.expires.Unix(), Digest: p.digest}
}
func (p *peer) fail() error { p.closed = true; return ErrAuthentication }

package keyfile

import (
	"bytes"
	"encoding/base64"
	"errors"

	"github.com/ktav-lang/golang/pure"
)

const (
	packetPrefix = 4*saltSize + nonceSize
	maxEnvelope  = 96 * 1024
)

type opaqueDocument struct {
	Data string `json:"data"`
}

type innerEnvelope struct {
	Version     int    `json:"version"`
	KDF         string `json:"kdf"`
	MemoryKiB   int    `json:"memory_kib"`
	Passes      int    `json:"passes"`
	Parallelism int    `json:"parallelism"`
	Layers      int    `json:"layers"`
	Cipher      string `json:"cipher"`
	Purpose     string `json:"purpose"`
	Payload     string `json:"payload"`
}

func newOpaqueDocument() (document, error) {
	d, err := newDocument()
	d.Version = 2
	return d, err
}

// Format validates public structure only; it does not authenticate the file.
func Format(encoded []byte) (int, error) {
	d, _, err := decode(encoded)
	return d.Version, err
}

func encodeOpaque(d document, ciphertext []byte) ([]byte, error) {
	header, _, _, err := d.header()
	if err != nil || d.Version != 2 {
		return nil, errors.New("invalid opaque profile")
	}
	packet := append([]byte(nil), header[len(header)-packetPrefix:]...)
	packet = append(packet, ciphertext...)
	body, err := pure.EmitCanonical(opaqueDocument{Data: base64.StdEncoding.EncodeToString(packet)})
	if err != nil {
		return nil, err
	}
	if len(body) > MaxSize {
		return nil, errors.New("opaque container is too large")
	}
	return []byte(body), nil
}

func decodeOpaque(encoded []byte) (document, []byte, error) {
	if len(encoded) > MaxSize {
		return document{}, nil, errors.New("opaque container is too large")
	}
	value, err := pure.LoadsStrict(string(encoded))
	if err != nil {
		return document{}, nil, errors.New("invalid opaque Ktav")
	}
	root, ok := value.(map[string]any)
	if !ok || len(root) != 1 {
		return document{}, nil, errors.New("invalid opaque fields")
	}
	text, ok := root["data"].(string)
	if !ok || len(text) > base64.StdEncoding.EncodedLen(packetPrefix+maxEnvelope+Layers*tagSize) {
		return document{}, nil, errors.New("invalid opaque data")
	}
	packet, err := base64.StdEncoding.Strict().DecodeString(text)
	if err != nil || base64.StdEncoding.EncodeToString(packet) != text ||
		len(packet) <= packetPrefix+Layers*tagSize || len(packet) > packetPrefix+maxEnvelope+Layers*tagSize {
		return document{}, nil, errors.New("invalid opaque packet")
	}
	d := document{Version: 2, KDF: "argon2id-x4-hkdf-sha256", MemoryKiB: MemoryKiB,
		Passes: argonPasses, Parallelism: argonThreads, Layers: Layers}
	for i := range 4 {
		d.Salts = append(d.Salts, base64.StdEncoding.EncodeToString(packet[i*saltSize:(i+1)*saltSize]))
	}
	d.Nonce = base64.StdEncoding.EncodeToString(packet[4*saltSize : packetPrefix])
	if _, _, _, err := d.header(); err != nil {
		return document{}, nil, err
	}
	return d, packet[packetPrefix:], nil
}

func wrapPayload(d document, plaintext []byte) ([]byte, error) {
	if d.Version == 1 {
		return append([]byte(nil), plaintext...), nil
	}
	envelope := innerEnvelope{Version: 2, KDF: d.KDF, MemoryKiB: d.MemoryKiB,
		Passes: d.Passes, Parallelism: d.Parallelism, Layers: d.Layers,
		Cipher: "aes-256-gcm-hkdf-sha256", Purpose: "storage", Payload: base64.StdEncoding.EncodeToString(plaintext)}
	body, err := pure.EmitCanonical(envelope)
	if err != nil {
		return nil, err
	}
	if len(body) > maxEnvelope {
		return nil, errors.New("encrypted envelope is too large")
	}
	return []byte(body), nil
}

func unwrapPayload(d document, plaintext []byte) ([]byte, error) {
	if d.Version == 1 {
		return plaintext, nil
	}
	defer clear(plaintext)
	if len(plaintext) > maxEnvelope {
		return nil, errors.New("invalid encrypted envelope size")
	}
	var envelope innerEnvelope
	if err := pure.LoadsInto(string(plaintext), &envelope); err != nil {
		return nil, errors.New("invalid encrypted envelope")
	}
	if envelope.Version != 2 || envelope.KDF != d.KDF || envelope.MemoryKiB != d.MemoryKiB ||
		envelope.Passes != d.Passes || envelope.Parallelism != d.Parallelism || envelope.Layers != d.Layers ||
		envelope.Cipher != "aes-256-gcm-hkdf-sha256" || envelope.Purpose != "storage" {
		return nil, errors.New("unsupported encrypted envelope profile")
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(envelope.Payload)
	if err != nil || len(payload) == 0 || len(payload) > MaxPlaintext || base64.StdEncoding.EncodeToString(payload) != envelope.Payload {
		clear(payload)
		return nil, errors.New("invalid encrypted payload")
	}
	canonical, err := wrapPayload(d, payload)
	defer clear(canonical)
	if err != nil || !bytes.Equal(canonical, plaintext) {
		clear(payload)
		return nil, errors.New("noncanonical encrypted envelope")
	}
	return payload, nil
}

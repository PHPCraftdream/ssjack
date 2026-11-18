package keyfile

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"runtime"
	"sync"

	"github.com/PHPCraftdream/ssjack/internal/kdfgate"
	"github.com/ktav-lang/golang/pure"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/ssh"
)

type deriveFunc func(password, salt []byte) []byte

func argonDerive(password, salt []byte) []byte {
	key := argon2.IDKey(password, salt, argonPasses, MemoryKiB, argonThreads, 32)
	// Reclaim the previous workspace before the next 1 GiB invocation.
	runtime.GC()
	return key
}

func masterKey(password []byte, salts [][]byte, derive deriveFunc) ([]byte, error) {
	if len(password) == 0 || len(password) > 16*1024 {
		return nil, errors.New("passphrase must contain 1 to 16384 bytes")
	}
	release, err := kdfgate.Acquire(context.Background())
	if err != nil {
		return nil, err
	}
	defer release()
	combined := make([]byte, 0, 4*32)
	defer func() { clear(combined) }()
	for _, salt := range salts {
		part := derive(password, salt)
		if len(part) != 32 {
			clear(part)
			return nil, errors.New("invalid Argon2id output")
		}
		combined = append(combined, part...)
		clear(part)
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, combined, nil, []byte("ssjack-key/v1/master")), key); err != nil {
		clear(key)
		return nil, err
	}
	return key, nil
}

func layer(master, baseNonce, header []byte, purpose string, index int) (cipher.AEAD, []byte, []byte, error) {
	domain := "ssjack-key/v1/"
	if bytes.HasPrefix(header, []byte("ssjack-key/v2\x00")) {
		domain = "ssjack-key/v2/"
	}
	context := binary.BigEndian.AppendUint32([]byte(domain+purpose+"/layer/"), uint32(index))
	key := make([]byte, 32)
	defer clear(key)
	if _, err := io.ReadFull(hkdf.New(sha256.New, master, nil, context), key); err != nil {
		return nil, nil, nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, err
	}
	nonce := append([]byte(nil), baseNonce...)
	counter := binary.BigEndian.Uint32(nonce[len(nonce)-4:]) ^ uint32(index)
	binary.BigEndian.PutUint32(nonce[len(nonce)-4:], counter)
	aad := append(append([]byte(nil), header...), context...)
	return aead, nonce, aad, nil
}

func encryptLayers(plaintext, master, nonce, header []byte, purpose string) ([]byte, error) {
	data := make([]byte, len(plaintext), len(plaintext)+Layers*tagSize)
	copy(data, plaintext)
	for index := range Layers {
		aead, layerNonce, aad, err := layer(master, nonce, header, purpose, index)
		if err != nil {
			clear(data)
			return nil, err
		}
		data = aead.Seal(data[:0], layerNonce, data, aad)
	}
	return data, nil
}

func decryptLayers(ciphertext, master, nonce, header []byte) ([]byte, error) {
	data := append([]byte(nil), ciphertext...)
	for index := Layers - 1; index >= 0; index-- {
		aead, layerNonce, aad, err := layer(master, nonce, header, "storage", index)
		if err != nil {
			clear(data)
			return nil, err
		}
		opened, err := aead.Open(data[:0], layerNonce, data, aad)
		if err != nil {
			clear(data)
			return nil, errors.New("failed to unlock encrypted key")
		}
		data = opened
	}
	return data, nil
}

// Seal encrypts the entire previous ciphertext on each of 1000 layers.
func Seal(plaintext, password []byte) ([]byte, error) {
	return seal(plaintext, password, argonDerive)
}

// SealVersion preserves an existing format; new containers use Seal.
func SealVersion(plaintext, password []byte, version int) ([]byte, error) {
	return sealVersion(plaintext, password, version, argonDerive)
}

func seal(plaintext, password []byte, derive deriveFunc) ([]byte, error) {
	return sealVersion(plaintext, password, 2, derive)
}

func sealVersion(plaintext, password []byte, version int, derive deriveFunc) ([]byte, error) {
	if version != 1 && version != 2 {
		return nil, errors.New("unsupported encrypted container version")
	}
	if len(plaintext) == 0 || len(plaintext) > MaxPlaintext {
		return nil, errors.New("private key payload must contain 1 to 65536 bytes")
	}
	d, err := newDocument()
	d.Version = version
	if err != nil {
		return nil, err
	}
	return sealDocument(d, plaintext, password, derive)
}

func sealDocument(d document, plaintext, password []byte, derive deriveFunc) ([]byte, error) {
	header, salts, nonce, err := d.header()
	if err != nil {
		return nil, err
	}
	master, err := masterKey(password, salts, derive)
	if err != nil {
		return nil, err
	}
	defer clear(master)
	envelope, err := wrapPayload(d, plaintext)
	if err != nil {
		return nil, err
	}
	defer clear(envelope)
	ciphertext, err := encryptLayers(envelope, master, nonce, header, "storage")
	if err != nil {
		return nil, err
	}
	defer clear(ciphertext)
	return encode(d, ciphertext)
}

func Open(encoded, password []byte) ([]byte, error) {
	return open(encoded, password, argonDerive)
}

func open(encoded, password []byte, derive deriveFunc) ([]byte, error) {
	d, ciphertext, err := decode(encoded)
	if err != nil {
		return nil, err
	}
	header, salts, nonce, err := d.header()
	if err != nil {
		return nil, err
	}
	master, err := masterKey(password, salts, derive)
	if err != nil {
		return nil, err
	}
	defer clear(master)
	plaintext, err := decryptLayers(ciphertext, master, nonce, header)
	if err != nil {
		return nil, err
	}
	return unwrapPayload(d, plaintext)
}

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

// Generate derives Ed25519 bytes from the secret and fresh public parameters.
func Generate(password []byte) ([]byte, []byte, error) {
	return generate(password, argonDerive)
}

func generate(password []byte, derive deriveFunc) ([]byte, []byte, error) {
	d, err := newOpaqueDocument()
	if err != nil {
		return nil, nil, err
	}
	return generateDocument(d, password, derive)
}

// GenerateRecovery also returns an owned plaintext payload for in-memory rotation.
func GenerateRecovery(password []byte) ([]byte, []byte, []byte, error) {
	d, err := newOpaqueDocument()
	if err != nil {
		return nil, nil, nil, err
	}
	return generateMaterial(d, password, argonDerive)
}

func generateDocument(d document, password []byte, derive deriveFunc) ([]byte, []byte, error) {
	encoded, public, plaintext, err := generateMaterial(d, password, derive)
	clear(plaintext)
	return encoded, public, err
}

func generateMaterial(d document, password []byte, derive deriveFunc) ([]byte, []byte, []byte, error) {
	header, salts, nonce, err := d.header()
	if err != nil {
		return nil, nil, nil, err
	}
	master, err := masterKey(password, salts, derive)
	if err != nil {
		return nil, nil, nil, err
	}
	defer clear(master)
	public, plaintext, err := generateIdentity(master, nonce, header)
	if err != nil {
		return nil, nil, nil, err
	}
	succeeded := false
	defer func() {
		if !succeeded {
			clear(plaintext)
		}
	}()
	envelope, err := wrapPayload(d, plaintext)
	if err != nil {
		return nil, nil, nil, err
	}
	defer clear(envelope)
	ciphertext, err := encryptLayers(envelope, master, nonce, header, "storage")
	if err != nil {
		return nil, nil, nil, err
	}
	defer clear(ciphertext)
	encoded, err := encode(d, ciphertext)
	if err != nil {
		return nil, nil, nil, err
	}
	succeeded = true
	return encoded, public, plaintext, nil
}

func generateIdentity(master, nonce, header []byte) ([]byte, []byte, error) {
	seed, err := deriveSeed(master, nonce, header)
	if err != nil {
		return nil, nil, err
	}
	defer clear(seed)
	private := ed25519.NewKeyFromSeed(seed)
	defer clear(private)
	public, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		return nil, nil, err
	}
	block, err := ssh.MarshalPrivateKey(private, "ssjack derived Ed25519 key")
	if err != nil {
		return nil, nil, err
	}
	defer clear(block.Bytes)
	return ssh.MarshalAuthorizedKey(public), pem.EncodeToMemory(block), nil
}

func deriveSeed(master, nonce, header []byte) ([]byte, error) {
	ciphertext, err := encryptLayers([]byte("ssjack derived Ed25519 seed v1"), master, nonce, header, "keygen")
	if err != nil {
		return nil, err
	}
	defer clear(ciphertext)
	seed := sha256.Sum256(ciphertext)
	return seed[:], nil
}

// Unlocked owns a memory-only master; Close must end its lifetime.
type Unlocked struct {
	mu     sync.Mutex
	master []byte
	d      document
}

func NewUnlocked(password []byte, version int) (*Unlocked, error) {
	return newUnlocked(password, version, argonDerive)
}

func newUnlocked(password []byte, version int, derive deriveFunc) (*Unlocked, error) {
	d, err := newDocument()
	if err != nil {
		return nil, err
	}
	d.Version = version
	_, salts, _, err := d.header()
	if err != nil {
		return nil, err
	}
	master, err := masterKey(password, salts, derive)
	if err != nil {
		return nil, err
	}
	return &Unlocked{master: master, d: d}, nil
}

func Unlock(encoded, password []byte) ([]byte, *Unlocked, error) {
	return unlock(encoded, password, argonDerive)
}

func unlock(encoded, password []byte, derive deriveFunc) ([]byte, *Unlocked, error) {
	d, ciphertext, err := decode(encoded)
	if err != nil {
		return nil, nil, err
	}
	header, salts, nonce, err := d.header()
	if err != nil {
		return nil, nil, err
	}
	master, err := masterKey(password, salts, derive)
	if err != nil {
		return nil, nil, err
	}
	plaintext, err := decryptLayers(ciphertext, master, nonce, header)
	if err != nil {
		clear(master)
		return nil, nil, err
	}
	payload, err := unwrapPayload(d, plaintext)
	if err != nil {
		clear(master)
		return nil, nil, err
	}
	d.Ciphertext = ""
	return payload, &Unlocked{master: master, d: d}, nil
}

func (u *Unlocked) Close() {
	if u == nil {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	clear(u.master)
	u.master = nil
}

// Seal reuses the authenticated salts/master but always generates a fresh nonce.
func (u *Unlocked) Seal(plaintext []byte) ([]byte, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.master) != 32 {
		return nil, errors.New("encrypted storage context is closed")
	}
	if len(plaintext) == 0 || len(plaintext) > MaxPlaintext {
		return nil, errors.New("invalid encrypted payload size")
	}
	d := u.d
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	d.Nonce = base64.StdEncoding.EncodeToString(nonce)
	header, _, _, err := d.header()
	if err != nil {
		return nil, err
	}
	envelope, err := wrapPayload(d, plaintext)
	if err != nil {
		return nil, err
	}
	defer clear(envelope)
	ciphertext, err := encryptLayers(envelope, u.master, nonce, header, "storage")
	if err != nil {
		return nil, err
	}
	defer clear(ciphertext)
	return encode(d, ciphertext)
}

// Open authenticates and decrypts a container made by this context's Seal
// without another KDF run. Containers with different salts or parameters are
// rejected so entries from another unlock cannot be mixed in.
func (u *Unlocked) Open(encoded []byte) ([]byte, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.master) != 32 {
		return nil, errors.New("encrypted storage context is closed")
	}
	d, ciphertext, err := decode(encoded)
	if err != nil {
		return nil, errors.New("invalid encrypted container")
	}
	header, _, nonce, err := d.header()
	if err != nil || !sameProfile(d, u.d) {
		return nil, errors.New("invalid encrypted container")
	}
	plaintext, err := decryptLayers(ciphertext, u.master, nonce, header)
	if err != nil {
		return nil, errors.New("invalid encrypted container")
	}
	payload, err := unwrapPayload(d, plaintext)
	if err != nil {
		clear(plaintext)
		return nil, errors.New("invalid encrypted container")
	}
	return payload, nil
}

func sameProfile(a, b document) bool {
	if a.Version != b.Version || a.KDF != b.KDF || a.MemoryKiB != b.MemoryKiB || a.Passes != b.Passes ||
		a.Parallelism != b.Parallelism || a.Layers != b.Layers || len(a.Salts) != len(b.Salts) {
		return false
	}
	for i := range a.Salts {
		if a.Salts[i] != b.Salts[i] {
			return false
		}
	}
	return true
}

// GenerateIdentity returns owned public/private payloads, never files.
func (u *Unlocked) GenerateIdentity() ([]byte, []byte, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.master) != 32 {
		return nil, nil, errors.New("encrypted storage context is closed")
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	d := u.d
	d.Nonce = base64.StdEncoding.EncodeToString(nonce)
	header, _, _, err := d.header()
	if err != nil {
		return nil, nil, err
	}
	return generateIdentity(u.master, nonce, header)
}

// SSHProxyBinding privately binds route and selected credentials under a distinct domain.
func (u *Unlocked) SSHProxyBinding(identity, credentials []byte) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	if u == nil || len(identity) == 0 || len(identity) > MaxPlaintext || len(credentials) == 0 || len(credentials) > 8192 {
		return result, errors.New("invalid SSH proxy binding input")
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.master) != 32 {
		return result, errors.New("encrypted storage context is closed")
	}
	derive := hmac.New(sha256.New, u.master)
	derive.Write([]byte("ssjack/ssh-proxy-binding/key/v1\x00"))
	key := derive.Sum(nil)
	defer clear(key)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("ssjack/ssh-proxy-binding/value/v1\x00"))
	var size [8]byte
	for _, value := range [][]byte{identity, credentials} {
		binary.BigEndian.PutUint64(size[:], uint64(len(value)))
		mac.Write(size[:])
		mac.Write(value)
	}
	copy(result[:], mac.Sum(nil))
	return result, nil
}

// SSHPasswordBinding returns an opaque grant binding, not an unkeyed verifier.
// Only the unlocked owner can recompute it; changing the vault master revokes it.
func (u *Unlocked) SSHPasswordBinding(identity, password []byte) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	if u == nil || len(identity) == 0 || len(identity) > MaxPlaintext || len(password) == 0 || len(password) > 4096 {
		return result, errors.New("invalid SSH password binding input")
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.master) != 32 {
		return result, errors.New("encrypted storage context is closed")
	}
	derive := hmac.New(sha256.New, u.master)
	derive.Write([]byte("ssjack/ssh-password-binding/key/v1\x00"))
	key := derive.Sum(nil)
	defer clear(key)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("ssjack/ssh-password-binding/value/v1\x00"))
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(identity)))
	mac.Write(size[:])
	mac.Write(identity)
	binary.BigEndian.PutUint64(size[:], uint64(len(password)))
	mac.Write(size[:])
	mac.Write(password)
	copy(result[:], mac.Sum(nil))
	return result, nil
}

// Package appstorecrypto owns dedicated app-store key material, not authority.
package appstorecrypto

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"runtime"
	"sync"
	"unicode/utf8"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchortls"
	"github.com/PHPCraftdream/ssjack/internal/appstorebudget"
	"github.com/PHPCraftdream/ssjack/internal/appstorefile"
	"github.com/PHPCraftdream/ssjack/internal/appstoreheader"
	"github.com/PHPCraftdream/ssjack/internal/kdfgate"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

var ErrInvalid = errors.New("invalid application-store master derivation input")
var ErrDerivation = errors.New("application-store master derivation failed")

type deriveFunc func(password, salt []byte) []byte

type masterState struct {
	mu    sync.Mutex
	key   [32]byte
	store [16]byte
	salts [4][32]byte
	ready bool
}

// Copies share owned state, so Close clears the same key through every handle.
type Master struct{ state *masterState }

func argonDerive(password, salt []byte) []byte {
	part := argon2.IDKey(password, salt, 1, 1048576, 1, 32)
	runtime.GC()
	return part
}

// Derive does not verify a passphrase, authenticate a snapshot or permit encryption.
func Derive(ctx context.Context, header appstoreheader.Header, passphrase []byte) (*Master, error) {
	return deriveAdmitted(ctx, header, passphrase, argonDerive)
}

func deriveAdmitted(ctx context.Context, header appstoreheader.Header, passphrase []byte, fn deriveFunc) (*Master, error) {
	if ctx == nil || !header.Valid() {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	release, err := appstorebudget.TryAcquire(header.StoreID())
	if err != nil {
		if errors.Is(err, appstorebudget.ErrBusy) {
			return nil, ErrBusy
		}
		return nil, ErrInvalid
	}
	defer release()
	return derive(ctx, header, passphrase, fn)
}

func derive(ctx context.Context, header appstoreheader.Header, passphrase []byte, fn deriveFunc) (*Master, error) {
	if ctx == nil || !header.Valid() || len(passphrase) == 0 || len(passphrase) > 16384 || fn == nil {
		return nil, ErrInvalid
	}
	owned := append([]byte(nil), passphrase...)
	var release func()
	defer func() {
		clear(owned)
		if release != nil {
			release()
		}
	}()
	if !utf8.Valid(owned) || bytes.IndexByte(owned, 0) >= 0 {
		return nil, ErrInvalid
	}
	var err error
	release, err = kdfgate.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	var combined [128]byte
	defer clear(combined[:])
	salts := header.Salts()
	for i := range salts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		part := fn(owned, salts[i][:])
		if len(part) != 32 {
			clear(part)
			return nil, ErrDerivation
		}
		copy(combined[i*32:(i+1)*32], part)
		clear(part)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	var key [32]byte
	defer clear(key[:])
	if _, err := io.ReadFull(hkdf.New(sha256.New, combined[:], nil, []byte("ssjack-appstore/v1/master")), key[:]); err != nil {
		return nil, ErrDerivation
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &Master{state: &masterState{key: key, store: header.StoreID(), salts: salts, ready: true}}, nil
}

func (m *Master) Closed() bool {
	if m == nil || m.state == nil {
		return true
	}
	m.state.mu.Lock()
	defer m.state.mu.Unlock()
	return !m.state.ready
}

// Matches checks the dedicated store/salt context, not snapshot authentication.
func (m *Master) Matches(header appstoreheader.Header) bool {
	if m == nil || m.state == nil || !header.Valid() {
		return false
	}
	m.state.mu.Lock()
	defer m.state.mu.Unlock()
	return m.state.ready && m.state.store == header.StoreID() && m.state.salts == header.Salts()
}

func (m *Master) Close() error {
	if m == nil || m.state == nil {
		return nil
	}
	m.state.mu.Lock()
	defer m.state.mu.Unlock()
	clear(m.state.key[:])
	m.state.ready = false
	return nil
}

const installationLayers = 1000
const maxInstallation = 256 << 10

var ErrInstallation = errors.New("invalid encrypted application-store installation")
var installationMagic = []byte("SSINST01")

type deriveFnType func(context.Context, appstoreheader.Header, []byte) (*Master, error)
type Binding struct {
	Endpoint       string
	RootsDER       [][]byte
	CertificateDER [][]byte
	PrivateDER     []byte
	ServiceKey     []byte
	Header         appstoreheader.Header
	// DirectoryDev and DirectoryIno bind this authenticated installation to
	// its protected store root. Their values must come from Store.Identity;
	// caller-authored values are not proof of directory identity.
	DirectoryDev uint64
	DirectoryIno uint64
}

func (b Binding) transport() (*appstoreanchortls.Writer, error) {
	if b.Endpoint == "" || len(b.Endpoint) > 2048 || !b.Header.Valid() || len(b.RootsDER) == 0 || len(b.RootsDER) > 16 || len(b.CertificateDER) == 0 || len(b.CertificateDER) > 8 || len(b.PrivateDER) == 0 || len(b.PrivateDER) > 1<<20 || len(b.ServiceKey) == 0 || len(b.ServiceKey) > 4096 {
		return nil, ErrInstallation
	}
	roots := x509.NewCertPool()
	for _, der := range b.RootsDER {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, ErrInstallation
		}
		roots.AddCert(cert)
	}
	chain := make([][]byte, len(b.CertificateDER))
	for n, der := range b.CertificateDER {
		if _, err := x509.ParseCertificate(der); err != nil {
			return nil, ErrInstallation
		}
		chain[n] = append([]byte(nil), der...)
	}
	key, err := x509.ParsePKCS8PrivateKey(b.PrivateDER)
	if err != nil {
		return nil, ErrInstallation
	}
	if private, ok := key.(ed25519.PrivateKey); ok {
		defer clear(private)
	}
	return appstoreanchortls.NewWriter(appstoreanchortls.Config{
		Endpoint: b.Endpoint, RootCAs: roots,
		Certificate: tls.Certificate{Certificate: chain, PrivateKey: key},
		ServiceKey:  b.ServiceKey, StoreID: b.Header.StoreID(),
	})
}

func (b Binding) Validate() error {
	w, err := b.transport()
	if err != nil {
		return ErrInstallation
	}
	return w.Close()
}

type Installation struct {
	master  *Master
	binding Binding
}

func (i *Installation) Header() appstoreheader.Header {
	if i == nil {
		return appstoreheader.Header{}
	}
	return i.binding.Header
}
func (i *Installation) Close() error {
	if i == nil {
		return nil
	}
	clear(i.binding.PrivateDER)
	i.binding.PrivateDER = nil
	if i.master != nil {
		return i.master.Close()
	}
	return nil
}
func (i *Installation) DirectoryMatches(dev, ino uint64) bool {
	return i != nil && dev != 0 && ino != 0 && i.binding.DirectoryDev == dev && i.binding.DirectoryIno == ino
}
func (i *Installation) Writer(directory *appstorefile.Directory) (*SnapshotWriter, *appstoreanchortls.Writer, error) {
	if i == nil || i.master == nil || i.master.Closed() || directory == nil {
		return nil, nil, ErrInstallation
	}
	dev, ino, err := directory.Identity()
	if err != nil || i.binding.Header.StoreID() != directory.StoreID() || !i.DirectoryMatches(dev, ino) {
		return nil, nil, ErrInstallation
	}
	transport, err := i.binding.transport()
	if err != nil {
		return nil, nil, err
	}
	writer, err := NewSnapshotWriter(directory, transport, i.master)
	if err != nil {
		_ = transport.Close()
		return nil, nil, err
	}
	return writer, transport, nil
}
func (i *Installation) CheckSnapshot(ctx context.Context, r io.Reader, expected ExpectedSnapshot) (SnapshotCheck, error) {
	if i == nil || i.master == nil {
		return SnapshotCheck{}, ErrInstallation
	}
	return i.master.CheckSnapshot(ctx, r, expected)
}
func NewInstallation(ctx context.Context, h appstoreheader.Header, p []byte, b Binding) ([]byte, error) {
	return newInstallation(ctx, h, p, b, Derive)
}
func newInstallation(ctx context.Context, h appstoreheader.Header, p []byte, b Binding, derive deriveFnType) ([]byte, error) {
	if ctx == nil || derive == nil || len(p) == 0 || len(p) > 16384 || !h.Valid() || b.Header != h || b.Validate() != nil {
		return nil, ErrInstallation
	}
	plain, err := marshalBinding(b)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	prefix := len(installationMagic) + appstoreheader.Size
	if len(plain) > maxInstallation-prefix-installationLayers*28 {
		return nil, ErrInstallation
	}
	m, err := derive(ctx, h, p)
	if err != nil {
		return nil, err
	}
	if m == nil || m.state == nil {
		if m != nil {
			_ = m.Close()
		}
		return nil, ErrInstallation
	}
	defer m.Close()
	m.state.mu.Lock()
	if !m.state.ready {
		m.state.mu.Unlock()
		return nil, ErrInstallation
	}
	key := m.state.key
	m.state.mu.Unlock()
	defer clear(key[:])
	hb := h.Bytes()
	aad := append(append([]byte(nil), installationMagic...), hb[:]...)
	defer clear(aad)
	out := append([]byte(nil), plain...)
	defer func() { clear(out) }()
	for n := 0; n < installationLayers; n++ {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		k := layerKey(key[:], n)
		block, e := aes.NewCipher(k)
		clear(k)
		if e != nil {
			return nil, ErrInstallation
		}
		a, e := cipher.NewGCM(block)
		if e != nil {
			return nil, ErrInstallation
		}
		nonce := make([]byte, a.NonceSize())
		if _, err = rand.Read(nonce); err != nil {
			clear(nonce)
			return nil, err
		}
		next := a.Seal(nonce, nonce, out, aad)
		clear(out)
		out = next
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	result := make([]byte, 0, len(aad)+len(out))
	result = append(result, aad...)
	result = append(result, out...)
	if len(result) > maxInstallation {
		clear(result)
		return nil, ErrInstallation
	}
	return result, nil
}
func UnlockInstallation(ctx context.Context, encoded, p []byte) (*Installation, error) {
	return unlockInstallation(ctx, encoded, p, Derive)
}
func unlockInstallation(ctx context.Context, encoded, p []byte, derive deriveFnType) (*Installation, error) {
	prefix := len(installationMagic) + appstoreheader.Size
	if ctx == nil || derive == nil || len(encoded) < prefix || len(encoded) > maxInstallation || len(p) == 0 || len(p) > 16384 || string(encoded[:len(installationMagic)]) != string(installationMagic) {
		return nil, ErrInstallation
	}
	h, err := appstoreheader.Parse(encoded[len(installationMagic):prefix])
	if err != nil {
		return nil, ErrInstallation
	}
	m, err := derive(ctx, h, p)
	if err != nil {
		return nil, err
	}
	if m == nil || m.state == nil {
		if m != nil {
			_ = m.Close()
		}
		return nil, ErrInstallation
	}
	m.state.mu.Lock()
	if !m.state.ready {
		m.state.mu.Unlock()
		_ = m.Close()
		return nil, ErrInstallation
	}
	key := m.state.key
	m.state.mu.Unlock()
	defer clear(key[:])
	aad := encoded[:prefix]
	out := append([]byte(nil), encoded[prefix:]...)
	defer func() { clear(out) }()
	for n := installationLayers - 1; n >= 0; n-- {
		if err = ctx.Err(); err != nil {
			_ = m.Close()
			return nil, err
		}
		k := layerKey(key[:], n)
		block, e := aes.NewCipher(k)
		clear(k)
		if e != nil {
			_ = m.Close()
			return nil, ErrInstallation
		}
		a, e := cipher.NewGCM(block)
		if e != nil || len(out) < a.NonceSize()+a.Overhead() {
			_ = m.Close()
			return nil, ErrInstallation
		}
		next, e := a.Open(nil, out[:a.NonceSize()], out[a.NonceSize():], aad)
		if e != nil {
			_ = m.Close()
			return nil, ErrInstallation
		}
		clear(out)
		out = next
	}
	b, err := unmarshalBinding(out)
	if err != nil || b.Header != h || b.Validate() != nil {
		clear(b.PrivateDER)
		_ = m.Close()
		return nil, ErrInstallation
	}
	if err = ctx.Err(); err != nil {
		clear(b.PrivateDER)
		_ = m.Close()
		return nil, err
	}
	return &Installation{master: m, binding: b}, nil
}
func layerKey(master []byte, n int) []byte {
	var info [20]byte
	copy(info[:16], []byte("SSJACK-INSTALL-v1"))
	binary.BigEndian.PutUint32(info[16:], uint32(n))
	k := make([]byte, 32)
	_, _ = io.ReadFull(hkdf.New(sha256.New, master, nil, info[:]), k)
	return k
}

const bindingLimit = 256 << 10

var errBinding = errors.New("invalid installation binding")

func putField(b *bytes.Buffer, v []byte) error {
	if len(v) > bindingLimit || b.Len()+4+len(v) > bindingLimit {
		return errBinding
	}
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(v)))
	b.Write(n[:])
	b.Write(v)
	return nil
}

func marshalBinding(v Binding) ([]byte, error) {
	if v.DirectoryDev == 0 || v.DirectoryIno == 0 || v.Validate() != nil {
		return nil, errBinding
	}
	var b bytes.Buffer
	var identity [16]byte
	binary.BigEndian.PutUint64(identity[:8], v.DirectoryDev)
	binary.BigEndian.PutUint64(identity[8:], v.DirectoryIno)
	b.Write(identity[:])
	if putField(&b, []byte(v.Endpoint)) != nil {
		return nil, errBinding
	}
	for _, list := range [][][]byte{v.RootsDER, v.CertificateDER} {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(list)))
		b.Write(n[:])
		for _, d := range list {
			if putField(&b, d) != nil {
				return nil, errBinding
			}
		}
	}
	if putField(&b, v.PrivateDER) != nil || putField(&b, v.ServiceKey) != nil {
		return nil, errBinding
	}
	h := v.Header.Bytes()
	if b.Len()+len(h) > bindingLimit {
		return nil, errBinding
	}
	b.Write(h[:])
	return b.Bytes(), nil
}

type bindingReader struct {
	b []byte
	i int
}

func (r *bindingReader) field() ([]byte, error) {
	if len(r.b)-r.i < 4 {
		return nil, errBinding
	}
	n := int(binary.BigEndian.Uint32(r.b[r.i:]))
	r.i += 4
	if n > bindingLimit || n > len(r.b)-r.i {
		return nil, errBinding
	}
	v := append([]byte(nil), r.b[r.i:r.i+n]...)
	r.i += n
	return v, nil
}

func unmarshalBinding(b []byte) (Binding, error) {
	var v Binding
	if len(b) > maxInstallation-8-appstoreheader.Size-1000*28 || len(b) > bindingLimit {
		return v, errBinding
	}
	fail := func() (Binding, error) {
		clear(v.PrivateDER)
		return Binding{}, errBinding
	}
	r := bindingReader{b: b}
	if len(b)-r.i < 16 {
		return fail()
	}
	v.DirectoryDev = binary.BigEndian.Uint64(b[r.i : r.i+8])
	v.DirectoryIno = binary.BigEndian.Uint64(b[r.i+8 : r.i+16])
	r.i += 16
	if v.DirectoryDev == 0 || v.DirectoryIno == 0 {
		return fail()
	}
	x, e := r.field()
	if e != nil {
		return fail()
	}
	v.Endpoint = string(x)
	clear(x)
	lists := []*[][]byte{&v.RootsDER, &v.CertificateDER}
	for z, dst := range lists {
		if len(b)-r.i < 4 {
			return fail()
		}
		n := int(binary.BigEndian.Uint32(b[r.i:]))
		r.i += 4
		limit := 16
		if z == 1 {
			limit = 8
		}
		if n == 0 || n > limit {
			return fail()
		}
		for j := 0; j < n; j++ {
			x, e = r.field()
			if e != nil {
				return fail()
			}
			*dst = append(*dst, x)
		}
	}
	v.PrivateDER, e = r.field()
	if e != nil {
		return fail()
	}
	v.ServiceKey, e = r.field()
	if e != nil {
		return fail()
	}
	if len(b)-r.i != appstoreheader.Size {
		return fail()
	}
	v.Header, e = appstoreheader.Parse(b[r.i:])
	if e != nil || v.Validate() != nil {
		return fail()
	}
	return v, nil
}

package wire

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"net"
	"time"
	"unicode/utf8"

	"github.com/ktav-lang/golang/pure"
)

const MaxFrame = 256 * 1024

type Auth struct {
	Version int    `json:"version"`
	Session string `json:"session"`
	Token   string `json:"token"`
}

type Reply struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	Data  string `json:"data,omitempty"`
}

type Request struct {
	Operation string `json:"operation"`
	Data      string `json:"data,omitempty"`
}

func RandomToken() (string, error) {
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}

func Write(w io.Writer, value any) error {
	text, err := pure.EmitCanonical(value)
	if err != nil {
		return err
	}
	data := []byte(text)
	if len(data) == 0 || len(data) > MaxFrame {
		return errors.New("Ktav frame has an invalid size")
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(data)))
	if err := writeAll(w, size[:]); err != nil {
		return err
	}
	return writeAll(w, data)
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func Read(r io.Reader, value any) error {
	var size [4]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(size[:])
	if n == 0 || n > MaxFrame {
		return errors.New("invalid Ktav frame size")
	}
	data := make([]byte, int(n))
	if _, err := io.ReadFull(r, data); err != nil {
		return err
	}
	if !utf8.Valid(data) || pure.LoadsInto(string(data), value) != nil {
		return errors.New("invalid Ktav message")
	}
	return nil
}

func Encode(value any) (string, error) {
	if value == nil {
		value = struct{}{}
	}
	text, err := pure.EmitCanonical(value)
	if err != nil {
		return "", errors.New("failed to encode Ktav data")
	}
	return text, nil
}

func Decode(data string, value any) error {
	if !utf8.ValidString(data) || pure.LoadsInto(data, value) != nil {
		return errors.New("invalid Ktav arguments")
	}
	return nil
}

func ServerTLS() (*tls.Config, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, "", err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "keykeeper-session"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, "", err
	}
	fingerprint := sha256.Sum256(der)
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	}, hex.EncodeToString(fingerprint[:]), nil
}

func ClientTLS(pin string) (*tls.Config, error) {
	expected, err := hex.DecodeString(pin)
	if err != nil || len(expected) != sha256.Size {
		return nil, errors.New("invalid keeper certificate fingerprint")
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		// Trust is pinned to this session's certificate rather than a system CA.
		InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) != 1 {
				return errors.New("keeper certificate verification failed")
			}
			cert := state.PeerCertificates[0]
			actual := sha256.Sum256(cert.Raw)
			if subtle.ConstantTimeCompare(expected, actual[:]) != 1 || time.Now().Before(cert.NotBefore) || time.Now().After(cert.NotAfter) {
				return errors.New("keeper certificate verification failed")
			}
			return nil
		},
	}, nil
}

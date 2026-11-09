package mcpchannel

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

// VersionRemoteMCP is intentionally distinct from the SSH broker protocol v2.
const VersionRemoteMCP = 1

const Env = "SSJACK_REMOTE_MCP_CHANNELS"

var ErrDescriptor = errors.New("invalid remote MCP channel descriptor")

type Descriptor struct {
	Version     int    `json:"version"`
	Ordinal     int    `json:"ordinal"`
	Session     string `json:"session"`
	Endpoint    string `json:"endpoint"`
	Pin         string `json:"pin"`
	Token       string `json:"token"`
	ExpiresUnix int64  `json:"expires_unix"`
}

func (d Descriptor) valid(now time.Time) bool {
	if d.Version != VersionRemoteMCP || d.Ordinal < 0 || d.Ordinal >= MaxChannels ||
		!tokenHex(d.Session) || !tokenHex(d.Token) || !tokenHex(d.Pin) || d.ExpiresUnix <= now.Unix() ||
		d.ExpiresUnix > now.Add(RuntimeLease).Unix()+1 || !localEndpoint(d.Endpoint) {
		return false
	}
	return true
}

func localEndpoint(endpoint string) bool {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil || host != "127.0.0.1" || port == "" || strings.Trim(port, "0123456789") != "" {
		return false
	}
	n, err := strconv.Atoi(port)
	return err == nil && n >= 1 && n <= 65535 && port == strconv.Itoa(n)
}

type callEnvelope struct {
	Tool  string `json:"tool"`
	Input string `json:"input"`
}

// EncodeDescriptors emits the only child environment value for these channels.
func EncodeDescriptors(descriptors []Descriptor) (string, error) {
	if validateDescriptors(descriptors, time.Now()) != nil {
		return "", ErrDescriptor
	}
	encoded, err := json.Marshal(descriptors)
	if err != nil || len(encoded) > 16<<10 {
		return "", ErrDescriptor
	}
	var canonical bytes.Buffer
	if json.Compact(&canonical, encoded) != nil || !bytes.Equal(canonical.Bytes(), encoded) {
		return "", ErrDescriptor
	}
	return string(encoded), nil
}

// DecodeDescriptors validates the complete value before any caller can connect.
func DecodeDescriptors(encoded string) ([]Descriptor, error) {
	if len(encoded) == 0 || len(encoded) > 16<<10 || !strictJSON(encoded) {
		return nil, ErrDescriptor
	}
	var descriptors []Descriptor
	decoder := json.NewDecoder(strings.NewReader(encoded))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if decoder.Decode(&descriptors) != nil || validateDescriptors(descriptors, time.Now()) != nil {
		return nil, ErrDescriptor
	}
	return descriptors, nil
}

func validateDescriptors(descriptors []Descriptor, now time.Time) error {
	if len(descriptors) < 1 || len(descriptors) > MaxChannels {
		return ErrDescriptor
	}
	ordinals, credentials, endpoints := map[int]bool{}, map[string]bool{}, map[string]bool{}
	for _, d := range descriptors {
		if !d.valid(now) || ordinals[d.Ordinal] || endpoints[d.Endpoint] ||
			d.Session == d.Token || d.Session == d.Pin || d.Token == d.Pin ||
			credentials[d.Session] || credentials[d.Token] || credentials[d.Pin] {
			return ErrDescriptor
		}
		ordinals[d.Ordinal], endpoints[d.Endpoint] = true, true
		credentials[d.Session], credentials[d.Token], credentials[d.Pin] = true, true, true
	}
	return nil
}

// strictDecode rejects duplicate and unknown Ktav envelope fields before decoding.
func strictDecode(data string, target any, fields ...string) error {
	if len(data) > MaxRequestBytes || wire.DecodeStrict(data, target, fields...) != nil {
		return ErrDescriptor
	}
	canonical, err := wire.Encode(target)
	if err != nil || canonical != data {
		return ErrDescriptor
	}
	return nil
}

func strictJSON(data string) bool {
	if !utf8.ValidString(data) {
		return false
	}
	decoder := json.NewDecoder(strings.NewReader(data))
	decoder.UseNumber()
	if !scanJSONValue(decoder, 0) {
		return false
	}
	_, err := decoder.Token()
	return err == io.EOF
}

func scanJSONValue(decoder *json.Decoder, depth int) bool {
	if depth > 64 {
		return false
	}
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	delim, isDelim := token.(json.Delim)
	if !isDelim {
		return true
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok || seen[key] || !scanJSONValue(decoder, depth+1) {
				return false
			}
			seen[key] = true
		}
		end, err := decoder.Token()
		return err == nil && end == json.Delim('}')
	case '[':
		for decoder.More() {
			if !scanJSONValue(decoder, depth+1) {
				return false
			}
		}
		end, err := decoder.Token()
		return err == nil && end == json.Delim(']')
	default:
		return false
	}
}

// MarshalCall returns the canonical Ktav call envelope; Input remains raw JSON text.
func MarshalCall(tool string, input []byte) ([]byte, error) {
	if tool == "" || len(tool) > MaxToolBytes || len(input) == 0 || len(input) > MaxClientInputBytes || !utf8.Valid(input) || !json.Valid(input) {
		return nil, ErrDescriptor
	}
	encoded, err := wire.Encode(callEnvelope{Tool: tool, Input: string(input)})
	if err != nil || len(encoded) > MaxRequestBytes {
		return nil, ErrDescriptor
	}
	return []byte(encoded), nil
}

func bootstrap(d Descriptor) broker.Bootstrap {
	return broker.Bootstrap{Session: d.Session, Endpoint: d.Endpoint, Pin: d.Pin, Token: d.Token}
}

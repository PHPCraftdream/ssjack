package legacy

import (
	"bytes"
	"errors"
	"io"
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type targetAddress string

func (a targetAddress) Network() string { return "tcp" }
func (a targetAddress) String() string  { return string(a) }

// HostPins imports only raw keys already trusted for this exact legacy address.
func HostPins(path, address string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, 1024*1024+1))
	file.Close()
	if readErr != nil || len(data) > 1024*1024 {
		return nil, errors.New("invalid known_hosts input size")
	}
	verify, err := knownhosts.New(path)
	if err != nil {
		return nil, errors.New("invalid legacy known_hosts file")
	}
	var pins []string
	seen := make(map[string]bool)
	for len(bytes.TrimSpace(data)) != 0 {
		marker, _, key, _, rest, err := ssh.ParseKnownHosts(data)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, errors.New("invalid known_hosts entry")
		}
		data = rest
		if marker != "" {
			continue
		}
		if _, certificate := key.(*ssh.Certificate); certificate {
			continue
		}
		if err := verify(address, targetAddress(address), key); err != nil {
			continue
		}
		identity := string(key.Marshal())
		if !seen[identity] {
			seen[identity] = true
			pins = append(pins, string(ssh.MarshalAuthorizedKey(key)))
		}
	}
	if len(pins) == 0 || len(pins) > 8 {
		return nil, errors.New("legacy address has no supported trusted raw host pins; verify and import server public keys explicitly")
	}
	return pins, nil
}

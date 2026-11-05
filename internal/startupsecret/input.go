package startupsecret

import "errors"

const Environment = "SSJACK_VAULT_PASSWORD"
const Maximum = 16384

var ErrInput = errors.New("invalid startup vault password: supply one nonempty --vault-password or SSJACK_VAULT_PASSWORD, at most 16384 bytes")
var ErrConsumed = errors.New("startup vault password has already been consumed")

type Input struct {
	value    []byte
	present  bool
	argument bool
	invalid  bool
	consumed bool
}

func New(value string, present bool) *Input {
	i := &Input{present: present}
	if present {
		i.assign(value)
	}
	return i
}

func (i *Input) assign(value string) {
	clear(i.value)
	i.value = nil
	i.invalid = len(value) == 0 || len(value) > Maximum
	if !i.invalid {
		i.value = []byte(value)
	}
}

func (i *Input) String() string { return "" }
func (i *Input) Supplied() bool { return i.present }

func (i *Input) Set(value string) error {
	if i.argument || i.consumed {
		i.Close()
		i.invalid = true
		return nil
	}
	i.argument, i.present = true, true
	i.assign(value)
	return nil
}

func (i *Input) Validate() error {
	if i.invalid {
		return ErrInput
	}
	return nil
}

func (i *Input) Read(fallback func() ([]byte, error)) ([]byte, error) {
	if err := i.Validate(); err != nil {
		return nil, err
	}
	if i.consumed {
		return nil, ErrConsumed
	}
	if !i.present {
		return fallback()
	}
	i.consumed = true
	value := i.value
	i.value = nil
	return value, nil
}

func (i *Input) Close() {
	clear(i.value)
	i.value = nil
	i.consumed = true
}

package launch

import (
	"errors"

	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/mcpchannel"
)

func validateRemoteMCP(mode broker.Mode, encoded string) error {
	if encoded == "" {
		return nil
	}
	if mode != broker.ModeFull {
		return errors.New("remote MCP channels are unavailable in declarative sessions")
	}
	if _, err := mcpchannel.DecodeDescriptors(encoded); err != nil {
		return errors.New("remote MCP channel descriptors are invalid")
	}
	return nil
}

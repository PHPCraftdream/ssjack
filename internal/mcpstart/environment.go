package mcpstart

import (
	"errors"
	"os"
	"strings"

	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/launch"
	"github.com/PHPCraftdream/ssjack/internal/mcpchannel"
)

var reservedEnvironment = []string{
	broker.EnvFile,
	broker.EnvToken,
	broker.EnvSession,
	broker.EnvEndpoint,
	broker.EnvPin,
	mcpchannel.Env,
	"SSJACK_APP_ENDPOINT",
	"SSJACK_APP_TOKEN",
	"SSJACK_APP_CERTIFICATE_SHA256",
}

// ReadEnvironment captures MCP bootstrap capabilities, scrubs their environment
// aliases, and validates the accepted entry in the current directory's fixed config.
func ReadEnvironment() (broker.Bootstrap, []mcpchannel.Descriptor, error) {
	return readEnvironment(os.Environ, os.Unsetenv, os.Getwd)
}

func readEnvironment(environ func() []string, unsetenv func(string) error, getwd func() (string, error)) (broker.Bootstrap, []mcpchannel.Descriptor, error) {
	values := make(map[string]string, len(reservedEnvironment))
	present := make(map[string]bool, len(reservedEnvironment))
	var capturedNames []string
	ambiguous := false
	for _, item := range environ() {
		name, value, ok := strings.Cut(item, "=")
		if !ok {
			continue
		}
		for _, canonical := range reservedEnvironment {
			if strings.EqualFold(name, canonical) {
				if name != canonical || present[canonical] {
					ambiguous = true
				}
				values[canonical], present[canonical] = value, true
				capturedNames = append(capturedNames, name)
				break
			}
		}
	}
	defer func() {
		for name := range values {
			values[name] = ""
		}
	}()

	var scrubFailed bool
	for _, name := range capturedNames {
		if unsetenv(name) != nil {
			scrubFailed = true
		}
	}
	if scrubFailed {
		return broker.Bootstrap{}, nil, errors.New("failed to clear reserved MCP bootstrap environment")
	}
	if ambiguous {
		return broker.Bootstrap{}, nil, errors.New("ambiguous reserved MCP bootstrap environment")
	}

	bootstrap := broker.Bootstrap{
		Session: values[broker.EnvSession], Endpoint: values[broker.EnvEndpoint],
		Pin: values[broker.EnvPin], Token: values[broker.EnvToken],
	}
	fail := func(err error) (broker.Bootstrap, []mcpchannel.Descriptor, error) {
		bootstrap.Token = ""
		return broker.Bootstrap{}, nil, err
	}
	if bootstrap.Endpoint == "" || bootstrap.Pin == "" || bootstrap.Session == "" || bootstrap.Token == "" {
		return fail(errors.New("start the MCP bridge through an ssjack session"))
	}
	root, err := getwd()
	if err != nil || launch.ValidateMCP(root) != nil {
		return fail(errors.New("MCP bridge requires an accepted entry in fixed .mcp.json"))
	}
	var descriptors []mcpchannel.Descriptor
	if present[mcpchannel.Env] {
		descriptors, err = mcpchannel.DecodeDescriptors(values[mcpchannel.Env])
		if err != nil {
			return fail(errors.New("remote MCP channel descriptors are invalid"))
		}
	}
	return bootstrap, descriptors, nil
}

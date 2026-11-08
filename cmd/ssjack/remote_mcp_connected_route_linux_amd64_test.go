//go:build linux && amd64

package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
)

const (
	remoteMCPConnectedEndpoint = "https://coordinator.invalid/mcp"
	remoteMCPConnectedRouteEnv = "SSJACK_REMOTE_MCP_FIXTURE_ROUTE"
)

type remoteMCPConnectedRoute struct {
	Address string `json:"address"`
	RootDER []byte `json:"root_der"`
}

// The public source deliberately cannot install a route. CI overlays this hook
// only alongside the private mcphttp transport registry.
func installRemoteMCPFixtureRoute(string, string, []byte) error {
	return errors.New("private remote MCP fixture route is unavailable")
}

func installRemoteMCPConnectedRouteFromEnvironment() error {
	encoded := os.Getenv(remoteMCPConnectedRouteEnv)
	_ = os.Unsetenv(remoteMCPConnectedRouteEnv)
	if len(encoded) == 0 || len(encoded) > 32<<10 {
		return errors.New("remote MCP fixture route metadata is unavailable")
	}
	data, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil || len(data) > 24<<10 {
		return errors.New("remote MCP fixture route metadata is invalid")
	}
	defer clear(data)
	var route remoteMCPConnectedRoute
	if json.Unmarshal(data, &route) != nil || len(route.RootDER) == 0 || len(route.RootDER) > 16<<10 {
		return errors.New("remote MCP fixture route metadata is invalid")
	}
	host, port, err := net.SplitHostPort(route.Address)
	if err != nil || host != "127.0.0.1" || port == "" || strings.Trim(port, "0123456789") != "" {
		return errors.New("remote MCP fixture route address is invalid")
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 || strconv.Itoa(number) != port {
		return errors.New("remote MCP fixture route address is invalid")
	}
	root, err := x509.ParseCertificate(route.RootDER)
	if err != nil || !root.IsCA {
		return errors.New("remote MCP fixture trust root is invalid")
	}
	return installRemoteMCPFixtureRoute(remoteMCPConnectedEndpoint, route.Address, route.RootDER)
}

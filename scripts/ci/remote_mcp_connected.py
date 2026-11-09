#!/usr/bin/env python3
"""Run connected remote-MCP acceptance with a narrow private route overlay."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = Path(__file__).resolve()
POLICY = ROOT / "internal" / "mcphttp" / "policy.go"
ROUTE_TEST = ROOT / "cmd" / "ssjack" / "remote_mcp_connected_route_test.go"
CONNECTED = ROOT / "cmd" / "ssjack" / "remote_mcp_connected_harness_test.go"
SCENARIOS = ("connected-basic", "connected-bypass", "connected-active-cancel", "connected-empty", "connected-cancel")
SUPPORTED_PLATFORMS = ("linux", "darwin", "win32")


def replace_once(source: str, old: str, new: str, label: str) -> str:
    if source.count(old) != 1:
        raise SystemExit(f"private connected overlay expected one {label}")
    return source.replace(old, new, 1)


def overlay_sources(directory: Path) -> dict[str, str]:
    policy = POLICY.read_text(encoding="utf-8")
    policy = replace_once(policy, '"crypto/tls"', '"crypto/tls"\n\t"crypto/x509"', "TLS import")
    policy = replace_once(policy, '"strings"\n\t"time"', '"strings"\n\t"sync"\n\t"time"', "sync import")
    start_marker = "func (p *endpointPolicy) transport() *http.Transport {"
    end_marker = "\nfunc rejectRedirect"
    if policy.count(start_marker) != 1 or policy.count(end_marker) != 1:
        raise SystemExit("private connected overlay expected one transport function and redirect boundary")
    start = policy.index(start_marker)
    end = policy.index(end_marker, start)
    if end <= start:
        raise SystemExit("private connected overlay transport boundary is invalid")
    transport = policy[start:end]
    transport = replace_once(transport, "return &http.Transport{", "base := &http.Transport{", "fixed transport")
    transport = replace_once(transport, "\n\t}\n}", "\n\t}\n\treturn privateFixtureTransport(p, base)\n}", "fixed transport return")
    policy = policy[:start] + transport + policy[end:]
    policy += PRIVATE_ROUTE_REGISTRY

    route = ROUTE_TEST.read_text(encoding="utf-8")
    route = replace_once(route, '"errors"\n\t"net"', '"errors"\n\t"net"\n\tmcphttp "github.com/PHPCraftdream/ssjack/internal/mcphttp"', "private route import")
    old_hook = '''func installRemoteMCPFixtureRoute(string, string, []byte) error {
	return errors.New("private remote MCP fixture route is unavailable")
}'''
    new_hook = '''func installRemoteMCPFixtureRoute(endpoint, address string, der []byte) error {
	return mcphttp.RegisterPrivateFixtureRoute(endpoint, address, der)
}'''
    route = replace_once(route, old_hook, new_hook, "closed test hook")
    policy_path = directory / "policy.go"
    route_path = directory / "remote_mcp_connected_route_test.go"
    policy_path.write_text(policy, encoding="utf-8")
    route_path.write_text(route, encoding="utf-8")
    return {str(POLICY.resolve()): str(policy_path.resolve()), str(ROUTE_TEST.resolve()): str(route_path.resolve())}


PRIVATE_ROUTE_REGISTRY = r'''
type privateFixtureRoute struct { address string; roots *x509.CertPool }
var privateFixtureRoutes = struct { sync.Mutex; values map[string]privateFixtureRoute }{values: make(map[string]privateFixtureRoute)}

// RegisterPrivateFixtureRoute exists only in this temporary source overlay.
func RegisterPrivateFixtureRoute(endpoint, address string, der []byte) error {
	if endpoint != "https://coordinator.invalid/mcp" || len(der) == 0 || len(der) > 16<<10 { return ErrTransport }
	host, port, err := net.SplitHostPort(address)
	if err != nil || host != "127.0.0.1" || port == "" || strings.Trim(port, "0123456789") != "" { return ErrTransport }
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 || strconv.Itoa(number) != port { return ErrTransport }
	certificate, err := x509.ParseCertificate(der)
	if err != nil || !certificate.IsCA || certificate.VerifyHostname("coordinator.invalid") != nil { return ErrTransport }
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	privateFixtureRoutes.Lock()
	defer privateFixtureRoutes.Unlock()
	if _, exists := privateFixtureRoutes.values[endpoint]; exists { return ErrTransport }
	privateFixtureRoutes.values[endpoint] = privateFixtureRoute{address: address, roots: roots}
	return nil
}

func privateFixtureTransport(policy *endpointPolicy, base *http.Transport) *http.Transport {
	if policy == nil || base == nil { return base }
	privateFixtureRoutes.Lock()
	route, ok := privateFixtureRoutes.values[policy.endpoint]
	privateFixtureRoutes.Unlock()
	if policy.endpoint == "https://coordinator.invalid/mcp" && (!ok || policy.host != "coordinator.invalid" || policy.port != "443") {
		base.DialContext = func(context.Context, string, string) (net.Conn, error) { return nil, ErrTransport }
		return base
	}
	if !ok { return base }
	if policy.endpoint != "https://coordinator.invalid/mcp" || policy.host != "coordinator.invalid" || policy.port != "443" { return base }
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	base.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if ctx == nil || ctx.Err() != nil || network != "tcp" && network != "tcp4" && network != "tcp6" || address != "coordinator.invalid:443" { return nil, ErrTransport }
		return dialer.DialContext(ctx, network, route.address)
	}
	config := base.TLSClientConfig.Clone()
	config.RootCAs, config.ServerName = route.roots, "coordinator.invalid"
	base.TLSClientConfig = config
	return base
}
'''


def main() -> int:
    if sys.platform not in SUPPORTED_PLATFORMS:
        raise SystemExit(f"connected remote MCP acceptance unsupported on {sys.platform}")
    with tempfile.TemporaryDirectory(prefix="ssjack-remote-mcp-connected-") as temporary:
        directory = Path(temporary)
        overlay = directory / "overlay.json"
        overlay.write_text(json.dumps({"Replace": overlay_sources(directory)}), encoding="utf-8")
        log_path = directory / "connected.log"
        env = os.environ.copy()
        env.pop("SSJACK_VAULT_PASSWORD", None)
        env["SSJACK_TEST_FULL_KDF"] = "1"
        env["SSJACK_TEST_REMOTE_MCP_CONNECTED"] = "1"
        command = ["go", "test", "-v", "-mod=readonly", "-p", "1", "-overlay", str(overlay), "-run", "^TestVaultRemoteMCPStartupFullProfile$", "-count=1", "-timeout", "900s", "./cmd/ssjack"]
        result = subprocess.run(command, cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False)
        log_path.write_text(result.stdout, encoding="utf-8")
        sys.stdout.write(result.stdout)
        if result.returncode:
            return result.returncode
        required = ["--- PASS: TestVaultRemoteMCPStartupFullProfile "]
        required += [f"--- PASS: TestVaultRemoteMCPStartupFullProfile/{name} " for name in SCENARIOS]
        required += [f"REMOTE-MCP-CONNECTED-OBSERVED:{name}" for name in SCENARIOS]
        missing = [marker for marker in required if marker not in result.stdout]
        skipped = re.findall(
            r"^[ \t]*--- SKIP: TestVaultRemoteMCPStartupFullProfile(?:/[^\s]+)? ",
            result.stdout,
            re.MULTILINE,
        )
        if missing or skipped:
            print("Connected acceptance evidence missing or skipped:", "; ".join(missing + skipped), file=sys.stderr)
            return 1
        return 0


if __name__ == "__main__":
    raise SystemExit(main())

# Per-server SSH proxies

Configure a route in `ssjack --interactive` → Servers → SERVER → **[Edit SSH proxy]**.
The setting is owned by the named server and shared by every SSH account on it.
New accounts inherit the same route. There is no per-command `--proxy` argument,
external proxy command, environment lookup or implicit fallback.

## Supported routes

| Type field | Behavior |
| --- | --- |
| `direct` | No proxy; removes saved proxy settings and credentials for all server accounts. Default for older databases. |
| `socks5` | SOCKS5 CONNECT, anonymous or username/password authentication (RFC 1929). Target DNS is resolved by the proxy, not locally. |
| `http` | HTTP/1.0 or HTTP/1.1 CONNECT, anonymous or explicitly configured Basic proxy authentication. Target authority is sent to the proxy without local target DNS lookup. |

Use `host:port` for **Proxy address**, not a URL. IPv6 literals require brackets.
Proxy DNS itself uses the OS resolver. Target addresses support ASCII hostnames,
IPv4 and IPv6; international names must be supplied in ASCII form. IPv6 zone IDs
are not supported through a proxy. Direct connections keep the existing behavior.

**Proxy login/password** are optional as a pair and must both be nonempty when
configured. Username is at most 255 bytes; SOCKS5 passwords at most 255 bytes,
HTTP proxy passwords at most 1024 bytes. Password input is masked, never prefilled
or returned in metadata. No credentials in URLs, argv, environment or logs.
HTTP Basic usernames cannot contain a colon.

Blank password preserves the existing credential only when type, proxy address
and login are unchanged. Changing any of those with authentication enabled
requires re-entry, preventing accidental disclosure of a retained password to a
new endpoint. Clear the login and leave the password empty to disable proxy auth.
Select `direct` explicitly to remove the route. Apply affects every account;
Cancel/Escape performs no change and clears owned form input.

## Security and lifetime

**The proxy authentication hop is not encrypted.** SOCKS5 username/password and
HTTP Basic over plain HTTP are visible to the proxy and an observer of that
network hop. Use a trusted proxy/network. HTTPS-to-proxy, SOCKS-over-TLS, NTLM,
Digest, proxy chains, SSH jump hosts and environment-driven bypass lists are not
implemented by this setting.

The SSH session inside the tunnel remains end-to-end encrypted. Independently
verified destination SSH host keys and evidence that the selected key/password
was actually offered remain mandatory; successful proxy authentication does not
substitute for SSH authentication. A failed proxy handshake, rejected credentials,
malformed/oversized response or timeout fails closed: no direct fallback, HTTP
redirect, alternate identity or automatic retry.

Dial plus proxy negotiation has a 10-second upper bound, shortened by caller
cancellation/deadline. HTTP response headers are bounded to 16 KiB. Buffered SSH
bytes following a CONNECT reply are preserved. Cancellation closes and joins the
owned negotiation scope. Proxy response bodies and authentication data are not
exposed as diagnostics.

Routing is attached to the selected owned credential, not a process-global map.
It covers human shell, `check`, key rotation, agent command/stream runners and
application/text-adapter SSH operations through their existing central dial path.
It does not proxy the keeper's loopback MCP bootstrap or application-store HTTPS
control plane. `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` and lowercase variants never
select the SSH route.

The owner menu sees edits in its authenticated RAM session; the next explicitly
chosen SSH connection uses those settings without another database unlock.
Other already-running keepers retain their captured credential/route snapshot:
restart them explicitly to adopt new settings. This is not live synchronization
or an OS-level egress firewall.

## Storage, grants and compatibility

Proxy settings/passwords are part of the encrypted credential payload (directory
schema v2). No container/KDF version is changed. Old no-proxy databases retain
direct behavior. Older strict binaries may reject the new optional `proxy` field;
keep an encrypted recovery copy before using extended settings. Legacy v1 payloads
do not support proxy settings. New databases use [directory schema v2](VAULT.md#current-directory-format) directly.

Owner export/import includes proxy settings and actual credentials in the selected
account records. Preview exposes type/address/login/auth-present metadata only,
never the password. Deliberate plaintext export therefore discloses proxy
credentials along with selected SSH credentials; encrypted export remains default.
Import preserves the shared-server rule and refuses conflicting or malformed data.

Text-adapter grants bind the exact selected route as well as SSH identity. Proxied
accounts use a domain-separated keyed binding under the authenticated database
master, including private proxy/SSH password material with length framing. This is
not an unkeyed password hash or secret getter. Changing route/authentication/master
requires matching new approval; ordinary encrypted saves keep the binding stable.
Existing direct-key/direct-password bindings remain unchanged. Captured external
secret refs never become latest, and changing settings does not extend old grants.
Explicit grant revocation remains separate from editing the database.

## Verification boundary

Regression sources cover protocol framing, authentication, remote DNS, IPv4/IPv6,
CONNECT read-ahead, refusals, cancellation, no environment/direct fallback,
actual SSH key/password/pin/evidence paths, archive round trips, encrypted reopen,
private grant binding and real-terminal proxy editing followed by SSH sessions.
Execution and readiness require exact-source GitHub CI; authored tests alone are
not PASS. No real operator proxy, account or database is a development fixture.

[Owner menu](application-store/OWNER-TUI.md) · [Credentials](VAULT.md) ·
[Text grants](application-store/TEXT-ADAPTER.md) · [Capability map](README.md)

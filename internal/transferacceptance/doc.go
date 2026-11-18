// Package transferacceptance hosts the end-to-end acceptance of the
// file-transfer feature (docs/FILE-TRANSFER.md): an in-process SSH server
// that really executes commands, reusable tree and payload helpers, the
// full in-process stack scenarios (runner, remote protocol, engine,
// manager, broker and MCP bridge) and the full-profile keeper acceptance
// against the cmd/ssjack CLI facade (implementation packages under
// cmd/ssjack/internal).
package transferacceptance

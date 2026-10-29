# Declarative common tool schemas

This isolated catalog constructs the six fixed proposed-v1 common tool schema pairs in contract order. `Catalog` returns a fresh slice; `Lookup` accepts exact tool names and rejects unsupported names with `ErrUnknownTool`. Schema documents are immutable canonical JSON strings. IDs and domain-separated pair digests are independent of sessions and enrollments.

Nullable non-enum types are emitted as `[non-null type, "null"]`. The contract appends null to nullable enums, but none of these six tools has a nullable enum. The bounded dynamic nodes for desired values and projections retain the contract's object root and permit arbitrary nested JSON. The distinct `CommonOrLegacySchemaDocument` contract node has the same structural form but is not an external schema document; this catalog does not expose a DTO schema for it. Common documents are not checked against the external dialect. Canonical JSON and domain digests do not validate application values, enforce lexical or purpose-specific bounds, or confer authority. Enrolled desired and projection schemas require separate validation.

This package does not provide legacy schemas, register tools, wire production runtime behavior, or implement authorization. The catalog contract is proposed, not approved. Zero-tool declarative MCP and deny-only operations remain unchanged; bridge, broker, and dispatcher are untouched.

External-package regression tests contain hand-authored canonical documents and independently recompute expected pair digests with standard-library SHA-256 rather than precomputed hex. Tests are implemented but NOT EXECUTED; no local verification was performed. Public GitHub CI is by the parent only; no CI result is claimed.

# External schema subset

This package implements an isolated, fail-closed subset of the proposed external
schema dialect. It is neither full proposed v1 nor general JSON Schema support.
It is not connected to production validation or authorization; a successful
validation does not authorize a value or establish enrollment, provenance, or a
digest binding. The proposed dialect is described in
[schemas.md](../../docs/declarative/schemas.md).

## Schema shape and supported keywords

Every schema, including each nested schema, must be a JSON object. It must have
`type` unless it has a type-less `enum` or `const`. Supported types are
`object`, `array`, `string`, `integer`, `boolean`, or `null`, or a two-element
array containing one non-null type and `null` in either order.
The root must contain exactly
`"$schema":"https://json-schema.org/draft/2020-12/schema"`; nested schemas
must not contain `$schema`. Boolean schemas are rejected.
Unknown keywords and keywords used with the wrong type are rejected.

A type-less enum and/or const may have annotations, but no type-specific
keywords. It matches only the exact finite bounded JSON values enumerated, or
their intersection when both constraints are present. Object values must match
in full: extra properties, including nested ones, do not match unless the entire
value is separately enumerated. A malformed or unsupported explicit `type` is
rejected. An untyped schema without enum or const (including an empty or
annotation-only schema) is rejected rather than allowing arbitrary objects.

All types may have `title` and `description` strings, `default` as any bounded
JSON value, and `examples` as an array of bounded JSON values. These annotations
never change validation. Nullable values still must satisfy `enum` and `const`;
other type-specific constraints apply only to the non-null type.

All types may have `enum` and/or `const`. `enum` must be an array of 1–256
canonically distinct JSON values. `const` may be any bounded JSON value. Both
are checked in addition to type and other constraints; the schema checker does
not require their values to match the declared type or other constraints. Equality
is canonical JSON equality, including for `uniqueItems`.

| Type | Mandatory shape | Other supported keywords |
| --- | --- | --- |
| object | `properties` object, `required` array containing each property name exactly once and no others, `additionalProperties:false`; every property value is a nested schema | `minProperties`, `maxProperties`: integers 0–128 |
| array | `items` is one nested schema; `maxItems` is an integer 0–256 | `minItems`: integer 0–256; `uniqueItems`: boolean |
| string | `maxLength` is an integer 1–4096 | `minLength`: integer 0–4096 |
| integer | none beyond `type` | `minimum`, `maximum`, `exclusiveMinimum`, `exclusiveMaximum`: safe integers; `multipleOf`: positive safe integer |
| boolean, null | none beyond `type` | none beyond `enum` and `const` |

Inclusive range endpoints are ordered; exclusive and inclusive numeric constraints
are applied independently, and contradictory constraints may be unsatisfiable.
Object values must contain exactly the declared properties;
array items each match `items`, and `uniqueItems:true` requires distinct items.
String length counts Unicode code points. A valid schema need not be satisfiable
(for example, property counts or `const` can conflict with other constraints).

## Deliberately rejected proposed v1 features

The subset rejects unsupported keywords, including `$ref`, `$defs`, patterns,
formats, composition and conditionals. No schema lookup is performed. It requires
explicit `type` except for finite enum or const nodes, closed object shape, array
`items`/`maxItems`, and string `maxLength`. The rejection of unconstrained
typeless schemas is the conservative proposed-v1 resolution, not a restriction
unique to this subset; other restrictions may reject documents permitted by the
proposed dialect. It does not determine schema satisfiability.

## Canonical JSON bounds

Both schema and value are first canonicalized by `internal/canonicaljson`:

- One strict JSON value; raw input at most 262144 bytes and canonical output at
  most 65536 bytes.
- Depth at most 16 edges from the root; at most 4096 value nodes (keys are not
  nodes); at most 256 elements per array and 128 properties per object.
- Valid UTF-8 and escapes; strings and keys must satisfy the canonical text
  rules, including NFC and rejection of controls and lone surrogates. Duplicate
  decoded object keys are rejected.
- Numbers must be integer tokens in the safe range
  -9007199254740991..9007199254740991; decimal and exponent forms are rejected.

These limits apply to the entire schema document too, including nested schemas,
`enum` and `const`, as well as to values. Canonicalization sorts object keys,
preserves array order, and emits compact JSON; raw input need not already be
canonical.

## API

- `ValidateSchema(raw []byte) error` checks canonical JSON and schema shape;
  it returns `nil` or `ErrSchema`.
- `Validate(schemaJSON, valueJSON []byte, limit int) error` first checks the
  schema (returning `ErrSchema` on failure), then requires `limit` in
  1..`canonicaljson.MaxOutput` (65536), canonicalizes the value, applies that
  canonical-byte cap, and checks it against the schema. Invalid limits, invalid
  or oversized values, and mismatches return `ErrValue`; success returns `nil`.
  The caller selects the appropriate context-specific value cap.

# External schema subset

This package implements an isolated, fail-closed subset of the proposed external
schema dialect. It is neither full proposed v1 nor general JSON Schema support.
It is not connected to production validation or authorization; a successful
validation does not authorize a value or establish enrollment, provenance, or a
digest binding. The proposed dialect is described in
[schemas.md](../../docs/declarative/schemas.md).

## Schema shape and supported keywords

Every schema, including each nested schema, must be a JSON object. It must have
`type` unless it has a type-less `enum`, `const`, or explicit closed object shape. Supported types are
`object`, `array`, `string`, `integer`, `boolean`, or `null`, or a two-element
array containing one non-null type and `null` in either order.
The root must contain exactly
`"$schema":"https://json-schema.org/draft/2020-12/schema"`; nested schemas
must not contain `$schema`. Boolean schemas are rejected.
Unknown keywords are rejected. Explicitly typed schemas may carry valid irrelevant type-specific keywords; every present keyword and nested schema is checked even when inapplicable. `properties` is an object of recursively valid schemas; `required` is an array of distinct strings; `additionalProperties` is boolean; `items` is a recursively valid schema; `uniqueItems` is boolean; and bounds obey the table below. Mismatched object keywords need not require every property and may set `additionalProperties:true`; mandatory closed-object, bounded-array and bounded-string shapes apply when that non-null type is explicitly declared.

A typeless finite-only schema admits `enum` and/or `const` plus annotations. A typeless closed object schema requires `additionalProperties:false` and a valid closed shape; it may also include `enum` and/or `const` and annotations. No other type-specific keywords are allowed in either form. Finite constraints match exact bounded JSON values, or their intersection when both are present; object contents must match in full. They constrain all values before object-only constraints are applied. A malformed explicit `type`, empty or annotation-only typeless schema is rejected. Closed shapes obey the object rules below, including omitted empty equivalents and extra required names; object keywords affect objects only, so non-objects pass those constraints.

All types may have `title` and `description` strings, `default` as any bounded
JSON value, and `examples` as an array of bounded JSON values. These annotations
never change validation. Nullable values still must satisfy `enum` and `const`;
other type-specific constraints apply only to the non-null type.

All types may have `enum` and/or `const`. `enum` must be an array of 1–256
canonically distinct JSON values. `const` may be any bounded JSON value. Both
are checked in addition to type and other constraints; the schema checker does
not require their values to match the declared type or other constraints. Equality
is canonical JSON equality, including for `uniqueItems`.

The table describes mandatory shape and applicable keywords for each declared
non-null type. Explicitly typed schemas may also carry valid inapplicable
keywords as described above.

| Type | Mandatory shape | Other supported keywords |
| --- | --- | --- |
| object | `additionalProperties:false`; `properties` and `required` may be omitted only as empty equivalents; `required` contains every declared property name and may contain extra names, without duplicates; every property value is a nested schema | `minProperties`, `maxProperties`: integers 0–128 |
| array | `maxItems` is an integer 0–256; `items` is one nested schema, required unless `maxItems` is 0 | `minItems`: integer 0–256; `uniqueItems`: boolean |
| string | `maxLength` is an integer 1–4096 | `minLength`: integer 0–4096 |
| integer | none beyond `type` | `minimum`, `maximum`, `exclusiveMinimum`, `exclusiveMaximum`: safe integers; `multipleOf`: positive safe integer |
| boolean, null | none beyond `type` | none beyond `enum` and `const` |

The proposed external dialect specifies individual bounds (schemas.md, external
schema dialect), but does not require min/max pairs to be ordered. Consequently
reversed `minProperties`/`maxProperties`, `minItems`/`maxItems`,
`minLength`/`maxLength`, and `minimum`/`maximum` are accepted when each bound
is individually valid. They cannot match their applicable type, but nullable
schemas can still match null, untyped closed object shapes can match non-objects,
and an explicitly declared different type can match because the bounds are
inapplicable.
Exclusive and inclusive numeric constraints apply independently.
Closed-shape object values must contain every declared property and no undeclared property; extra required names make a closed object unsatisfiable.
Array items each match `items`, and `uniqueItems:true` requires distinct items.
For a declared array, omitting `items` is allowed only for explicitly valid
`maxItems:0`; other declared types may omit `items` freely. If present, `items`
must still be a valid nested schema, even when inapplicable. Nonempty arrays
cannot match `maxItems:0`.
String length counts Unicode code points. A valid schema need not be satisfiable
(for example, property counts or `const` can conflict with other constraints).

## Features outside the external dialect

The subset rejects unsupported keywords, including `$ref`, `$defs`, patterns,
formats, composition and conditionals. No schema lookup is performed. It requires
explicit `type` except for finite enum/const nodes or untyped closed object shapes, closed object shape, array `maxItems` (and `items` except at zero), and string `maxLength`. The
mandatory bounds for explicitly typed arrays and strings also apply to the
proposed external contract, including nullable and nested schemas; they are not
full JSON Schema requirements. The rejection of unconstrained typeless schemas is
also a proposed-v1 restriction. The two implementations remain separate and statically reviewed, not formally proven equivalent. Unsupported full JSON Schema features are outside the chosen dialect, not evidence of a dialect gap. Broader proposed-v1 enrollment, authenticated distribution, authorization, descriptor and runtime integration remain separate gaps; admission does not determine satisfiability.

Compatibility: there is no automatic migration or rewrite; unchanged documents retain canonical bytes and pins, and changed schemas require new digests and enrollment. `internal/enrollmentvalidator/references.go` calls S; `internal/enrollmentrecord/record.go` calls the separate P implementation. `internal/driverprocess` and `internal/immutableexec` use structural checks only.

Preexisting standalone pinned raw admission gaps remain: P's `ValidatePinnedValue` calls `ParseJSON` with a 65536-byte raw cap, whereas S uses canonicaljson's 262144-byte raw cap. A null padded to 65537 bytes is accepted by S but rejected by P with `ErrInvalid`. P rejects `-0`; canonicaljson normalizes it to zero, so S accepts it under an integer schema while P returns `ErrInvalid`. Shared schema canonicalization and digest do not imply whole-API equivalence. No parser changes or protocol frame broadening are implied; the separate 65536-byte frame cap is unchanged. No CI results currently exist; public CI is by the parent only.

## Canonical JSON bounds

Both schema and value are first canonicalized by `internal/canonicaljson`. The
262144-byte raw input cap is also an explicit restriction of the proposed external
contract, distinct from canonical and context-specific output caps and from full
JSON Schema:

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

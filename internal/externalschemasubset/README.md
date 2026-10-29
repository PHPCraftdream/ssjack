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
Unknown keywords are rejected. On explicitly typed schemas, object, array,
string-length, and integer keywords may accompany a different type. They constrain
only instances of their applicable type, but every present keyword is checked:
`properties` is an object of recursively valid schemas; `required` is an array
of distinct strings; `additionalProperties` is a boolean (schema-valued forms are
unsupported); `items` is a recursively valid schema; `uniqueItems` is boolean;
and all bounds obey the table below. These checks also apply when the keyword is
inapplicable, including for nullable schemas and `maxItems:0`. Mismatched
`properties` need not all be required, and mismatched `additionalProperties` may
be true; the mandatory closed-object shape and bounded-array shape still apply
when the declared non-null type is object or array respectively. Untyped shapes
remain restricted as described below. Full proposed-contract treatment remains unresolved.

A type-less enum and/or const without an object shape may have annotations, but no type-specific
keywords. It matches only the exact finite bounded JSON values enumerated, or
their intersection when both constraints are present. Object values must match
in full: extra properties, including nested ones, do not match unless the entire
value is separately enumerated. A malformed or unsupported explicit `type` is
rejected. An untyped schema without enum, const, or an explicit closed object shape
(including an empty or annotation-only schema) is rejected rather than allowing arbitrary objects.

An untyped closed object shape requires `additionalProperties:false` and follows
all object shape rules in the table below, including nested schemas and property
bounds. Object keywords apply only to objects: non-object values pass those
keywords. `enum` and `const`, if present, still constrain every value. No other
type-specific keywords may be combined with this shape.

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
Object values must contain exactly the declared properties;
array items each match `items`, and `uniqueItems:true` requires distinct items.
For a declared array, omitting `items` is allowed only for explicitly valid
`maxItems:0`; other declared types may omit `items` freely. If present, `items`
must still be a valid nested schema, even when inapplicable. Nonempty arrays
cannot match `maxItems:0`.
String length counts Unicode code points. A valid schema need not be satisfiable
(for example, property counts or `const` can conflict with other constraints).

## Deliberately rejected proposed v1 features

The subset rejects unsupported keywords, including `$ref`, `$defs`, patterns,
formats, composition and conditionals. No schema lookup is performed. It requires
explicit `type` except for finite enum/const nodes or untyped closed object shapes, closed object shape, array `maxItems` (and `items` except at zero), and string `maxLength`. The
mandatory bounds for explicitly typed arrays and strings also apply to the
proposed external contract, including nullable and nested schemas; they are not
full JSON Schema requirements. The rejection of unconstrained typeless schemas is
also a proposed-v1 restriction. Other subset restrictions may reject documents
permitted by the proposed dialect or reflect unresolved differences; this package
does not determine schema satisfiability.

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

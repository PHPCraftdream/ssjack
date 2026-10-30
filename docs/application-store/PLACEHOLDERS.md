# Exact versioned secret placeholders

## Metadata format

A placeholder contains reference metadata only. It is not a secret value, consumer grant, human approval, historical expectation or authority to decrypt. The only format is the following closed JSON object:

```json
{"$ssjack":{"format":"ssjack-secret-ref-v1","object_id":"22222222222222222222222222222222","snapshot_id":"44444444444444444444444444444444","store_id":"11111111111111111111111111111111","version_id":"33333333333333333333333333333333"}}
```

All four IDs are exactly 16 nonzero bytes encoded as 32 lowercase hexadecimal characters. Store, object, version and snapshot are all required. There are no aliases, wildcard/latest selectors, optional IDs, credential fields, endpoints, filesystem paths, payloads or application-specific fields.

`internal/appstoreplaceholder.Encode` accepts only a typed exact `appstoreref.Ref` and returns deterministic JCS-SSJACK-1 bytes. `Parse` accepts one object of at most 1024 raw bytes, validates JSON through the existing bounded canonicalizer, checks the closed shape and returns an owned exact Ref. Presentation whitespace/key order and valid escaped spellings may normalize; duplicate decoded keys still fail. Unknown/missing/null fields, invalid UTF-8/escapes, trailing data, other versions and noncanonical IDs fail with an opaque error that does not echo input values.

## Declaration and adapter boundary

Nix and Clawwright can retain this object unchanged as deployment declaration data. It is not automatically a valid native application's password setting. A trusted external adapter must recognize the marker, preserve exact identity and bind an approved consumer operation before any handoff. Core serialization contains no Nix/Clawwright business logic.

A Nix expression may parse a declaration JSON containing only references. Nix evaluation/build outputs must never resolve the reference to plaintext, put values in derivations or interpolate them into a generated environment/file. The secret-bearing operation remains outside evaluation, in the approved runtime consumer channel.

A Clawwright recipe may retain the same reference object rather than a literal value. This codec alone does not implement recipe walking, native OpenClaw providers, managed deployment, live adoption or backup/restore. Unsupported managed delivery must refuse before mutation; it must not fall back to `.env`, command arguments, operator environment or persistent target plaintext files. Existing standalone native reference mechanisms are not implicitly rewritten.

Do not scan and interpolate arbitrary strings. The `$ssjack` envelope is explicit, versioned and closed. The codec neither opens files nor looks up a store/current version and never collects, accepts a typed secret-value parameter or returns plaintext.

## Consumer binding

The composed internal CI scenario writes a snapshot, encodes its returned reference, parses the placeholder, checks the requested Ref against an independently fixed native-consumer binding and delivers the selected object through the protected spool. A different valid placeholder cannot choose another object outside that fixed binding. The native fixture independently verifies received bytes.

Production release is still private/disabled until authenticated enrollment and policy ownership exist. Parsing success, a matching code hash, UID, TTY or caller-supplied configuration is not that authority. Current-reference delivery still authenticates the anchor; historical delivery still needs independently trusted captured expectations and authorization, not a filename or supplied hash.

The complete product path—operator enrollment, native application adapters, reference-only backup/restore and observed adoption—remains unfinished. The codec and its synthetic composed test must not be presented as end-to-end Nix/Clawwright production readiness.

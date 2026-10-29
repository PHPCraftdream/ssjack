# Disconnected declarative descriptor validation

This package validates only a COMPLETE proposed-v1 declarative descriptor. It is disconnected from discovery, broker, bridge, dispatch and MCP. Full and legacy descriptors and incomplete zero-tool descriptors are rejected. It does not authenticate sessions or authorize tools, and does not integrate a runtime or select files, configuration or registries.

`Validate` returns a copy-safe `Descriptor`; `ID`, `SessionID`, `CanonicalJSON`, and `Tools` expose immutable strings and a fresh tool slice. `ErrInvalid` identifies rejected inputs. Common schema documents are compared as canonical JSON against the fixed declarative catalog; they are not passed to an external schema dialect. The descriptor ID is derived, not a wire field.

The shared canonical JSON limits apply to the entire descriptor, including its wrapper: 262144 raw bytes, 65536 canonical bytes, depth 16 edges, 4096 value nodes, 256 array elements, and 128 object properties. Duplicate decoded keys, invalid Unicode, controls, non-integers and unsafe integers are rejected. The independent fixture includes the deepest catalog constructions; its acceptance is covered by an authored test, not an executed result.

Tests were authored but NOT EXECUTED locally. CI is the parent operator's responsibility; no CI result is claimed here. Oversized structural witnesses independently check shared canonicalizer rejection and descriptor rejection; because these witnesses also violate the fixed descriptor shape, they do not isolate resource-limit enforcement inside `Validate`. The raw-byte boundary uses an otherwise valid descriptor.

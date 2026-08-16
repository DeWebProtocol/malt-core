# ProofList Format

ProofList is verifier-facing evidence returned with MALT resolve and primitive
read results, and by UnixFS content adapters. It records ordered authenticated
relations from a trusted root.

## Status

ProofList has no standalone operation discriminator. It is embedded in the
profiled `malt.resolve/v0alpha1`, `malt.read/v0alpha1`, and
`malt.map-proof/v0alpha1` results. Its named JSON
Schema is checked in at `protocol/schemas/prooflist.schema.json`; incompatible
result-contract revisions require a new enclosing profile.

Portable verification is implemented by `auth/verifier`. It performs no
ArcTable, CAS, runtime, layout, server, daemon, or network lookup.

## Envelope

The current Go shape is `auth/proof/prooflist.ProofList`:

| Field | JSON | Meaning |
| --- | --- | --- |
| `Root` | `root` | Trusted MALT structure root for this proof. |
| `Query` | `query` | Optional query/path string the proof was assembled for. |
| `Steps` | `steps` | Ordered proof steps. |

`ValidateShape(RequireSteps())` rejects an undefined root, an empty step list,
unknown step kinds, undefined `from` CIDs, undefined `target` CIDs on
traversal steps, and any step whose `from` CID does not continue from the
current target. The sole exception is a terminal `map_absence` step, whose
target must be undefined and serializes as JSON `null`.

## Step Kinds

| Kind | Role |
| --- | --- |
| `map_step` | Authenticates a keyed map relation. |
| `map_absence` | Terminal proof that an exact keyed map relation is absent; requires `structure/map` evidence and an undefined target. |
| `payload_binding` | Authenticates the optional reserved terminal `@payload` map binding when a layout uses it. |
| `list_index` | Authenticates one list index binding. |
| `list_range` | Authenticates measured-list byte range metadata and covered segments. |
| `blob_binding` | Binds a resolved structure target to an immutable blob target. |
| `implicit_block` | Compatibility evidence for implicit block traversal. |
| `legacy_unknown` | Legacy adapter marker retained for older evidence. |

List evidence is label-checked: `list_index` must carry
`evidence_kind="structure"` and `evidence_backend="list"`, while `list_range`
must carry `evidence_kind="structure"` and
`evidence_backend="measured_list"`.

## Step Fields

Each step has:

- `kind`
- `from`
- `target`
- optional query fields: `query`, `coordinate`, `path`, `index`
- optional range fields: `start`, `end`, `length`, `child_count`,
  `total_size`, `chunk_size`, `segments`
- optional proof labels: `evidence_kind`, `evidence_backend`
- opaque proof bytes: `evidence`, `proof`

The byte fields are JSON-encoded by Go's standard `encoding/json` rules for
`[]byte`, currently base64 strings.

## Ordering Rules

Steps form a linear chain unless they are terminal list evidence:

1. The first step starts at `root`.
2. Non-list traversal steps advance the current target to `step.target`.
3. A `map_absence` step is terminal, does not advance to a target, and must use
   `structure/map` evidence.
4. List index or list range evidence may appear at the terminal phase.
5. No later traversal step may appear after terminal map or list evidence.

This shape validation is structural. `auth/verifier` then selects a
verification-only backend from the typed root and checks the map/list evidence.
The verifier must reject unsupported or mismatched evidence labels rather than
falling back to runtime state.

## Typed Read Binding

The root `malt` facade binds a ProofList to a typed read before accepting it:

```text
ReadRequest{Root, Query}
ReadResult{Target, Segments, ProofList}
VerifyRead(request, result)
```

`VerifyRead` requires the ProofList root and query to match the request, exactly
one primitive proof step whose kind and coordinate match the typed query, the
last proof target to match `ReadResult.Target`, and range segments to match
`ReadResult.Segments`. This rejects cross-kind confusion such as satisfying a
list query with a valid map proof for a similarly named key. Only after those
bindings pass does it delegate cryptographic and semantic checks to
`auth/verifier`.

The `v0alpha1` `Query.Kind` values are `map_key`, `list_index`, and
`list_range`. Their current ProofList `query` labels are:

| Query kind | ProofList `query` label |
| --- | --- |
| `map_key` | canonical map key/path text |
| `list_index` | `list:<index>` |
| `list_range` | `range:<start>:<end>`; an empty end means authenticated EOF |

Map query labels are compared using the canonical coordinate rules in
`auth/arcset`. Portable verification does not trim whitespace or apply
HTTP/UnixFS path cleaning. Transport and application adapters may enforce their own
path policy before constructing a typed query.

These encodings remain experimental and consumers must pin a MALT release.
The byte-level map/list envelopes inside `evidence` and `proof` are specified in
[Commitment and proof encoding](./commitment-proof-encoding.md). Cross-language
accept/reject behavior is locked by the
[Resolve/Read conformance corpus v2](./resolve-read-conformance-v2.md).

## Serialization And Transport

ProofLists are embedded in the operation-specific `malt.resolve/v0alpha1`,
`malt.read/v0alpha1`, and `malt.map-proof/v0alpha1` results. Core does not define HTTP headers, omission
switches, content routes, or cache variance. A transport must preserve the
serialized request/result fields required by local verification.

## Range Evidence

UnixFS large-file byte-range reads currently use:

1. map/path proof to the file object
2. terminal `@payload` proof to the list root
3. one measured-list `list_range` step over the requested byte interval

The `list_range` step carries fixed chunk metadata, covered segment CIDs, and
metadata/index proof bytes. Verifiers must reject range proofs that shift byte
boundaries, omit covered segment bindings, or mismatch the measured metadata.

`@payload` is reserved but optional in generic map state. The UnixFS model
requires it and therefore emits the terminal payload-binding step shown above;
a generic relation-only map ProofList does not need such a step.

The `list_range` step authenticates range metadata and segment CIDs, not raw
payload bytes by itself. A client that accepts returned range bytes
must:

1. verify the ProofList against the trusted root,
2. fetch or otherwise resolve each authenticated segment CID, and
3. apply its application-specific range composition and CID byte-binding check
   before trusting the body.

The first-party UnixFS implementation of that check lives in
the MALT local runtime (currently `DeWebProtocol/malt-client`), not in core.

## Related Proposals

- [MIP-1003](../mips/mip-1003-prooflist-verification-schema.md) tracks
  verifier-contract stabilization beyond the released `v0alpha1` profile.
- [MIP-1006](../mips/mip-1006-variable-size-measured-list-evidence.md) tracks a
  future variable-size measured-list model.
- [MIP-1011](../mips/mip-1011-arc-authentication-core-contract.md) defines the
  typed read/result binding around this evidence.

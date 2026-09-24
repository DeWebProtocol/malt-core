# Typed authentication query contract

The sole current query profile is `malt.authentication/3`. The schemas in
`protocol/schemas/authentication-request.schema.json`,
`authentication-result.schema.json`, and `authentication-verification.schema.json`
are transport neutral. Core owns no HTTP routes.

## Request

| Field | Meaning |
| --- | --- |
| `profile` | Exactly `malt.authentication/3` |
| `root` | Caller-selected complete self-describing V0 Root CID |
| `steps` | At most 256 explicit application labels, evaluated in order |
| `operation` | `resolve`, `binding`, or `range` |
| `label` | Required only for `binding` |
| `start`, `end` | Decimal-string byte offsets; start required for `range`, end optional |

`resolve` permits no primitive input/range fields. `binding` permits only its
label. `range` permits start and optional end, with end no smaller than start.
Typed input grammar and layout restrictions are fixed by
[authentication inputs](authentication-inputs.md). Each reached Root supplies
its own derivation profile and exact VC profile. Empty traversal still validates the
initial Root and installed rules/profiles.

There is no string path parser, longest-prefix grouping, inferred backend, or
implicit terminal selector. Applications choose every step. A full flat path
can be one AA=4 label; a rooted path supplies separate selectors. The label `@payload` has no special Core meaning.

Applications currently assume a single valid resolution chain. The explicit
step verifier authenticates the selected chain, not that construction
assumption. Longest-match may guide an outer traversal search, but these
proofs do not assert longest-match selection or uniqueness and do not require
absence proofs for unselected longer labels.

## Result and verification

A result has the same profile, `resolved`, and ordered `traversal` evidence.
A successful `resolve` has neither `binding` nor `range`. `binding` contains
one `engine.Result`; `range` contains an `engine.RangeResult`. The caller's
selected operation determines the only permitted result shape.

`authentication.Verify(engine, request, result)` verifies the complete Root,
steps, ordered continuity, target, and final primitive evidence. It performs no
I/O. A server-authored request is not a trust anchor: the client must construct
or independently match the request to its intended Root and query.

If a traversal binding is missing, `absent_step` is its zero-based decimal
index. `resolved` is empty, there is no primitive result, and traversal contains
exactly the successful prefix followed by the missing-binding proof. The
verifier authenticates this termination, not the remaining suffix. Unsupported
inputs, cancellation, corrupt materialization, and recovery/I/O errors are not
absence.

Prefix absence ends at a proved empty slot or a terminal different full key.
Positional absence authenticates count metadata showing the index is outside
`[0,count)`. Both use `malt.binding/0` node evidence. A binding's `present` and
target are checked against this evidence, never accepted as assertions.

A fixed-chunk Positional range authenticates metadata, bounds, and precisely the
ordered segment bindings selected by the byte interval. Applications must
check payload bytes against segment CIDs and compose the requested slice.
Authentication alone does not prove availability, freshness, or byte integrity
of an arbitrary HTTP response.

## Encoding

Decoders reject duplicate keys, non-exact field names, unknown fields, trailing
JSON, missing required fields, null values where the schema disallows them,
noncanonical base64, retired tagged inputs, and retired query profiles. Required arrays must be
present as arrays even when empty; optional defaults and nullable fields follow
the published schemas. Documents are bounded at 96 MiB with nesting depth at
most 256. Unsigned 64-bit numbers use canonical decimal strings. Byte fields
use standard base64 strings rather than JSON numeric arrays. CID-valued primitive fields
use IPLD links; request/root summary fields use CID strings as their schemas
specify. Error text is diagnostic, not a conformance identifier.

See [commitment and proof encoding](commitment-proof-encoding.md) and the
[current conformance corpus](conformance-corpora.md).

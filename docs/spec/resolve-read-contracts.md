# Resolve And Read Contracts

This document defines the current transport-neutral result contracts for MALT
core. They are operation-specific: ProofList is evidence for a resolve or read,
not a generic operation envelope.

## Profiles And Schemas

| Contract | Profile | Go values |
| --- | --- | --- |
| path resolution | `malt.resolve/v0alpha1` | `malt.ResolveRequest`, `malt.ResolveResult`, `malt.VerifyResolve` |
| primitive semantic read | `malt.read/v0alpha1` | `malt.ReadRequest`, `malt.ReadResult`, `malt.VerifyRead` |
| map membership or non-membership | `malt.map-proof/v0alpha1` | `malt.MapProofRequest`, `malt.MapProofResult`, `malt.VerifyMapProof` |

Serialized values live in `github.com/dewebprotocol/malt-core/protocol`. Checked-in
JSON Schemas live in `protocol/schemas/` and are embedded through
`protocol.Schema` and `protocol.SchemaNames`.

Cross-language accept/reject behavior for resolve and read is locked by the
[Resolve/Read conformance corpus v2](./resolve-read-conformance-v2.md).
Map-proof behavior is covered by KZG/IPA runtime, portable-verifier, protocol,
and WASM registration tests; it does not alter the frozen resolve/read corpus.

## Resolve

A request carries the caller-selected root and canonical segment array:

```json
{
  "profile": "malt.resolve/v0alpha1",
  "root": "b...root",
  "segments": ["docs", "readme", "@payload"]
}
```

The untrusted executor returns:

```json
{
  "profile": "malt.resolve/v0alpha1",
  "target": "b...payload",
  "prooflist": {
    "root": {"/": "b...root"},
    "query": "docs/readme/@payload",
    "steps": []
  }
}
```

The empty `steps` array above is abbreviated; a non-empty segment path requires
real evidence. A client verifies the original request and returned result
together:

```go
err := verifier.VerifyResolve(ctx, protocol.ResolveVerification{
    Request: request,
    Result: result,
})
```

Verification binds the trusted root, exact segment path, ordered proof steps,
terminal target, and all commitment evidence.

### Explicit `@payload`

Payload materialization is not an implicit special result:

- `segments: []` is strict zero-step root identity and requires `target == root`;
- `segments: ["@payload"]` authenticates the root object's payload CID; and
- `segments: ["a", "b", "@payload"]` authenticates a nested payload CID.

UnixFS clients append `@payload` when they want bytes. Other applications may
use the same reserved core coordinate without adopting UnixFS path syntax.

### Existential Selection

Resolution authenticates one complete derivation selected by the executor. It
does not prove that the derivation was globally longest, shortest, unique, or
preferred by an application. If several authenticated derivations could serve
an application request, choosing among them is application/client policy. Each
accepted result still proves its own root-to-target relation.

## Primitive Read

Read is the proof-bearing primitive formerly named `prove` in the frozen
artifact profile. It accepts exactly one typed query:

- `map_key` with a non-empty segment array;
- `list_index` with `index`; or
- `list_range` with `start` and optional exclusive `end`.

Example:

```json
{
  "profile": "malt.read/v0alpha1",
  "root": "b...map",
  "query": {"kind": "map_key", "segments": ["name"]}
}
```

The result carries `target`, optional ordered `range_segments`, and
`prooflist`. `VerifyRead` binds those fields to the original typed request.
Read is intentionally primitive; multi-root prefix consumption belongs to
resolve.

## Map Membership And Non-Membership

`Read` preserves its existing target-oriented behavior: a missing map key
returns `ErrQueryNotFound`. A caller that needs proof of either outcome uses the
separate map-proof contract:

```json
{
  "profile": "malt.map-proof/v0alpha1",
  "root": "b...map",
  "key": ["name"]
}
```

A present result carries `present: true`, a target CID, and a normal
`map_step` (or terminal `payload_binding`) step. An absent result carries
`present: false`, omits the result target, and terminates with a
`map_absence` step whose `target` is JSON `null`. The step contains
`structure/map` evidence proving `mapping.Binding{Present:false}` at the exact
root and key; `null` is not evidence by itself.

`VerifyMapProof` binds the caller-selected root and canonical key to the
presence discriminator, conditional target, one proof step, and its
cryptographic evidence. A proof for another key, a membership proof relabeled
as absence, or an absence proof relabeled as membership is rejected.

## Transport Projection

These contracts are transport-neutral. HTTP gateways commonly expose JSON
resolve and read endpoints, while RPC and language SDKs may carry segment
arrays directly. Route naming, authentication, CORS, limits, and service error
policy are not defined by core. The current managed projection is documented
in the independent `DeWebProtocol/gateway` repository.

HTTP may use `/` as an application projection between segments. Application
syntaxes such as Unix paths or JavaScript `.` and `[]` remain client concerns.

## Payload Bytes And Mutation

A verified payload resolve authenticates a CID, not arbitrary response bytes.
Clients must also hash full raw/manifest bytes to the authenticated CID, or
validate application-defined ranged segments against authenticated segment
CIDs.

Semantic mutation inputs and writer receipts remain separate contracts. A
receipt describes execution and a candidate new root; it is not a delta or
state-transition proof. MALT will only introduce a proof-bearing mutation
result after its transition semantics and verification algorithm exist.

# Client-Root Contract

This document defines the transport-neutral contract for computing one exact
candidate root from complete, client-verified semantic state. It does not
define an HTTP route, persistence engine, root-publication policy, or portable
state-transition proof.

## Status

This contract is included in v0.0.7-rc.1 as an experimental pre-v1 surface.
The `/v1` suffixes below version serialized profiles; they do not declare
MALT or its Go source APIs stable at v1. Client-root bundles and receipts
retain the explicit non-claims defined below.

## Profiles And Schemas

| Contract | Profile | Schema |
| --- | --- | --- |
| complete old-state closure | `malt.update-view/v1` | `update-view.schema.json` |
| output-free requested change | `malt.semantic-intent/v1` | `semantic-intent.schema.json` |
| exact locally computed submission | `malt.client-root-bundle/v1` | `client-root-bundle.schema.json` |
| map proof-serving witness | `malt.client-root-materialization/v1` | `client-root-materialization.schema.json` |
| browser-local computation result | `malt.writer-compute-result/v2` | `writer-compute-result-v2.schema.json` |
| durable exact-bundle acknowledgement | `malt.materialization-receipt/v1` | `materialization-receipt.schema.json` |

Canonical in-process values live in `mutation`. Their JSON projections and
checked-in schemas live in `protocol`. The application-neutral computation
facade lives in `sdk/writer`.

These profiles are experimental pre-v1 contracts. Unknown profiles and values
that cannot be normalized to a valid canonical form must be rejected. An
incompatible wire revision requires a new profile identifier.

## Lifecycle And State Boundaries

```text
caller-selected accepted base root
  -> caller-bounded, untrusted complete UpdateView
  -> locally verified complete semantic vectors
  -> for a new state only: client-computed canonical empty-map base witness
  -> application-produced SemanticIntent
  -> locally computed transition outputs and candidate root
  -> root-bound map materialization for every map transition output
  -> exact ClientRootBundle
  -> service accepts that exact candidate or rejects the bundle
  -> exact MaterializationReceipt
  -> writer session may retain the candidate as its next working base
  -> optional publication and client trust promotion remain separate
```

`sdk/writer.Session.Load` verifies the complete view before installing it.
`Prepare` computes a candidate without advancing retained state.
`AcceptReceipt` advances only that SDK writer session after validating an exact
receipt for the sealed prepared result. It does not modify an application's
accepted-root store or perform publication.

## Complete Update View

`UpdateView` is the complete old semantic closure required to compute an
update locally:

- `base_root` is selected by the client;
- every typed MALT object reachable from that root occurs exactly once;
- every object contains its complete canonical logical vector and commit
  descriptor;
- object IDs and roots are unique, and objects are canonicalized by object ID;
- semantic child target kinds must agree with their typed MALT CIDs;
- unrelated objects, missing semantic children, cycles, excessive depth, and
  root/kind/backend mismatches are rejected; and
- positive object, total-entry, and depth bounds are part of the returned view
  and its digest.

Receiving an update view does not make it trusted. `sdk/writer` normalizes the
view, recomputes every declared object root with the backend encoded in that
root CID, and only then returns a `VerifiedUpdateView`.

The current state profile is `stateful-complete-vectors-v1`. Partial deltas,
server-selected snapshots, and proofs of only the changed coordinates cannot
be substituted for this complete-view contract.

Transport-specific clients should choose acceptable bounds before requesting a
view and require the response to preserve them. Core validates the bounds
carried by the value; it does not define the request route or transport policy.
The independent wire ceilings below apply even if a returned view declares
larger values.

## Semantic Intent

`SemanticIntent` describes the requested semantic change without supplying the
candidate root. Each transition:

- names the old or newly created logical object;
- declares map/list kind and commitment backend;
- carries canonical before/after changes;
- may consume the output of another transition by ID; and
- declares the expected number of parent uses.

Each existing or newly created object ID may occur in at most one transition.
Normalization checks before-images against the verified view; rejects duplicate
coordinates, no-op changes, target relabeling, missing outputs, cycles, orphan
outputs, and use-count mismatches; and produces a deterministic
child-before-parent order. The designated top transition must update the
base-root object and have zero parent uses. The client, not the service,
computes its root.

Application syntax and provenance are outside this value. A UnixFS client, an
object client, or another application translates its own change into the same
canonical intent without placing Unix paths, source objects, or evaluation
metadata in this Core profile.

## Canonical Ordering And Digests

Conversions to Core values and canonical constructors normalize ordering before
semantic validation and digest computation. Newly emitted wire values therefore
use:

- update-view objects are ordered lexicographically by `object_id`;
- each object's ArcSet uses its canonical coordinate order;
- changes within a transition are ordered by canonical coordinate bytes;
- transitions use deterministic child-before-parent topological order, with
  lexicographic transition ID breaking ties;
- bundle outputs are ordered by `transition_id`; and
- payload CIDs are unique and ordered by raw CID bytes.

The three digests are SHA-256 over canonical binary values, not hashes of JSON
text. Implementations use these encoding primitives:

| Value | Encoding |
| --- | --- |
| byte string or UTF-8 string | unsigned 64-bit big-endian byte length, then bytes |
| CID | the preceding byte-string encoding of the CID's raw bytes; an undefined CID encodes as an empty byte string |
| unsigned 32/64-bit integer | fixed-width big-endian |
| optional target | one byte `0` when absent; otherwise `1`, target-kind string, then CID |
| commit descriptor | one byte `0` for default; otherwise `1`, `total_size` uint64, then `chunk_size` uint64 |

`UpdateView.Digest` writes, in order: profile, state profile, base CID,
`max_objects`, `max_total_entries`, `max_depth`, object count, then for each
canonical object its ID, root CID, kind, canonical `ArcSet.MarshalBinary`
bytes, and commit descriptor.

`SemanticIntent.Digest` requires an intent already returned by
`NormalizeSemanticIntent`; it has no update-view argument and does not itself
normalize or validate before-images. It writes: profile, base CID, top output
ID, transition count, then for each canonical transition its ID, object ID,
old-root CID, kind, backend, commit descriptor, expected-use count, change
count, and each change's coordinate bytes, before target, after target, output
ID, and output kind. A digest caller must still bind the intent to its update
view; the intent digest alone does not authenticate before-images.

`ClientRootBundle.Digest` writes: profile, operation ID, the 32-byte view and
intent digests as length-prefixed byte strings, candidate CID, canonical output
count and output pairs, then canonical payload-CID count and values. On the
wire, all three digests are exactly 64 lowercase hexadecimal characters.

## Exact Client-Root Bundle

`sdk/writer.Runtime.ComputeBundle` applies a normalized intent to a verified
view and returns:

- every intermediate transition output;
- the designated candidate root;
- the exact set of literal payload CIDs introduced by the intent;
- deterministic SHA-256 digests of the canonical view and intent; and
- an operation ID and one canonical `ClientRootBundle` binding all of those
  values.

The bundle contains exactly one output for every transition. Each output's
typed root kind and commitment backend must match its transition, and the
bundle candidate must equal the designated top transition output. Its payload
set must equal the unique literal non-MALT CAS post-images introduced by the
intent. A service may reject the bundle, but it must not replace the candidate
with a different root while claiming to accept that bundle.

Payload CIDs in the bundle support service-side availability checks. Their
presence does not prove that payload bytes are durable, published, fresh, or
authorized for another reader.

`sdk/writer.NewRuntime` emits V0 Roots, including when the supplied complete
view uses historical V3 Roots. `NewHistoricalRuntime` is only for exact V3
replay. Current native/WASM equality is frozen in `conformance/client-root/v2`;
the independent v1 corpus retains historical outputs unchanged. The `/v2`
corpus revision and existing `/v1` wire profiles are separate from Root `V=0`.

Browser clients may invoke the same computation through
`cmd/malt-writer-wasm`. Its `maltComputeClientRootV1` entry point strictly
decodes bounded UTF-8 JSON `Uint8Array` values for an `UpdateView` and
`SemanticIntent`, runs `sdk/writer`, and returns a strictly validated
`malt.writer-compute-result/v2` carrying the canonical bundle, root-bound map
materialization, complete next view, and diagnostic local timings. The
materialization contains backend-owned radix cache coordinates for every map
transition output. The first result after `Session.BootstrapMap` additionally
contains `materialization.base`, a witness for the canonical empty-map base.
Both are untrusted until validated against their declared roots and complete
logical views. The WASM adapter does not contact a
service or change publication or trusted-root state. The v1 result schema is
retained for decode compatibility but is no longer emitted.

## Strict JSON Decoding And Limits

The client-root JSON decoders reject:

- unknown, duplicate, missing, or `null` fields at every nested level;
- malformed explicit optional-value discriminators;
- trailing JSON values;
- noncanonical CID, coordinate, target-kind, digest, and profile values; and
- semantic values that satisfy JSON Schema shape but violate the Core
  invariants above.

Fields are required unless their schema explicitly marks them optional.
Existing semantic before/after values use explicit `present` or `absent` state
objects. The sole optional client-root materialization member is `base`; it is
omitted outside bootstrap and explicit JSON `null` is rejected.

Before structural validation, every client-root document is limited to 64 MiB.
The wire contract additionally caps:

| Resource | Maximum |
| --- | ---: |
| objects | 65,536 |
| total entries | 1,048,576 |
| semantic depth | 65,536 |
| transitions | 65,536 |
| changes | 1,048,576 |
| payload CIDs | 1,048,576 |
| encoded CID string | 4,096 bytes |
| materialization entries | 4,194,304 |

The positive bounds inside an `UpdateView` may be lower than those hard
ceilings. Both the declared bounds and the independent wire ceilings are
enforced.

## Service Validation, Import, And Receipt

A service importing client-computed map roots must independently:

1. bind the bundle base to its authoritative current state and validate the
   complete view, canonical digests, normalized intent, output identities, and
   candidate selection;
2. derive each map transition's complete logical post-view from the validated
   before-image and normalized changes;
3. require exactly one materialization witness for every map output and call
   `radix.ValidateMaterialization` against that declared output root and logical
   post-view;
4. when `materialization.base` is present, require a single-object canonical
   empty-map bootstrap view and validate that base witness at the declared base
   root without calling `Commit`;
5. reject unsupported output kinds unless it has an equivalent root-bound
   importer for them;
6. check the required payload CIDs at its declared durability boundary;
7. atomically persist every accepted proof-serving witness entry and the
   service head/publication state named by its durability boundary; and
8. return a `MaterializationReceipt` only after that boundary succeeds.

`radix.ValidateMaterialization` depends on `IndexVerifier` and
`IndexRootProver`; it opens caller-supplied vectors through `ProveAtRoot` and
does not call `Commit`. The service therefore verifies and imports the exact
client root instead of recomputing a replacement candidate. The witness is
proof-serving state, not a portable transition proof.

Core defines the receipt value and its binding to one exact canonical bundle,
not the service's transaction, idempotency, persistence, or HTTP mechanism.
`durable_boundary` is a service-defined non-empty identifier; it is not a
portable proof that an arbitrary remote system actually completed those
writes.

A valid receipt binds:

- the operation ID;
- base and candidate roots;
- the canonical bundle digest; and
- the service-declared durable boundary.

Receipt validation requires the exact operation ID, base root, candidate root,
canonical bundle digest, and a non-empty durable-boundary identifier. It does
not independently inspect the service's storage.

## Explicit Non-Claims

An `UpdateView`, `ClientRootBundle`, writer computation result, or
`MaterializationReceipt` is not:

- a cryptographic state-transition or delta proof;
- proof that the service published the candidate as a named root or head;
- proof of freshness, rollback resistance, or multi-writer ordering;
- proof that another client should trust the candidate;
- authorization to read or write the associated data; or
- a substitute for local verification of later resolve/read results.

Trusted-root promotion remains client policy. Publication, head arbitration,
authorization, persistence, and application synchronization remain outside
MALT core.

## Creation Boundary

A browser writer may create the canonical empty-map base through
`sdk/writer.Session.BootstrapMap` (or `maltWriterBootstrapSessionV1`). The
commitment is computed in the selected client backend. The returned update view
is retained in the same stateful session, and its first prepared
`malt.writer-compute-result/v2` carries `materialization.base`.

Core accepts that optional witness only when the bundle view contains exactly
one object named `root`, its kind is map, its logical vector is empty, and its
root equals the bundle base. A service validates and atomically imports the
base and first candidate witnesses through root-bound proof operations; it does
not call `Commit` or substitute another bootstrap root. Whether a Bucket is
still eligible for first-root creation remains service concurrency policy.

## Related Documents

- [Resolve and read contracts](./resolve-read-contracts.md)
- [Writer receipts](./writer-receipts.md)
- [CID and wire format](./cid-and-wire-format.md)
- [Compatibility policy](../policy/compatibility.md)

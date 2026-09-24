# MALT Core Architecture

MALT Core is an application-neutral authentication SDK. Correctness is relative
to the full caller-selected Root and typed query. Materializers and remote
executors supply untrusted data; they do not select the client's trust anchor.

## Data model and authentication choices

An **ArcSet** is a set of application `label → target` bindings. Labels are
opaque bytes; targets are CIDs, which can themselves be MALT Roots. Applications
and Gateway-owned ArcTables retain the submitted label–target bindings for
recovery and future writes.

Authentication derives a coordinate from each label and binds it to the target:

```text
application label --coordinate derivation--> coordinate
coordinate + target --authentication layout + commitment--> Root
```

| Choice | Meaning |
| --- | --- |
| Coordinate derivation | `SHA256` derives a 32-byte coordinate using Core's domain-separated framing; `Direct` parses an already canonical coordinate |
| Authentication layout | `Prefix` organizes 32-byte keys; `Positional` organizes dense integer indices `[0, count)` |
| Commitment profile | An exact KZG or IPA parameter set and encoding, identified in the Root |
| ArcSet organization | The application's choice to group bindings in one Root or compose several Roots; this is not encoded in the Root |

`Direct` accepts exactly 32 key bytes or eight unsigned big-endian index bytes.
Use `coordinate.EncodeKey` or `coordinate.EncodeIndex`; a decimal text label such
as `"42"` is not an encoded index. Prefix accepts Direct or SHA256 derivation;
Positional requires Direct index labels.

The Root identifies the derivation profile, authentication layout, and exact
commitment profile. Coordinate derivation belongs outside `auth`; authentication
trees operate on coordinates. The Root format remains experimental `V=0`,
independently of the SDK version and CIDv1's container version.

Traversal accepts explicit label steps. A slash or `@payload` inside a label has
no built-in meaning. Applications currently assume a single valid resolution
chain; a longest-match search can be an outer lookup strategy, but Core proofs
authenticate the selected chain and do not prove uniqueness or longest-match
selection. See [authentication inputs and Roots](docs/spec/authentication-inputs.md)
and [query contracts](docs/spec/authentication-contracts.md).

## Layering

```text
derivation -> auth/coordinate -> auth/tree -> auth/commitment
                    engine binds coordinate derivation to the Root
                    traversal composes explicit steps across Roots
                    sdk/authentication supplies queries and retained writers
                    sdk/object constructs vertices from Go object references
                    protocol defines serialized operation contracts
                    maltcid defines Root and node identity encodings
```

`auth/tree` owns canonical Prefix/Positional node construction, affected-path
updates, snapshots, and binding/range evidence. It receives coordinates and
installed exact VC profiles and operation-specific capabilities; it knows no label grammar, application graph, payload
selector, or persistent store policy. `engine` applies the Root's coordinate derivation
profile before entering the tree. Every traversal hop uses the descriptor of the
Root reached by the preceding authenticated binding.

`maltcid` is the shared lower-level package for Root descriptors, exact VC
profile identities and CID/node encoding. It depends on no authentication,
derivation, traversal, protocol or SDK package. `protocol` supplies typed
serialized contracts, strict decoding and runtime validation alongside its
published JSON schemas and Markdown specifications.

`commitment.Committer`, `Prover`, and `Verifier` are independent capabilities.
The profile registry records identity and capacity; individual operations require
only their relevant capabilities. Both KZG and IPA expose verification-only types
without execution methods. The SDK stays backend-neutral; `builtin.NewVerifier`
is an opt-in constructor that imports the built-in verification implementations.

## Packages and integration boundaries

Go integrations typically start with `sdk/authentication`, `engine`, `maltcid`,
and a commitment backend. The module-root package contains documentation; it
does not forward the SDK API.

| Package | Responsibility |
| --- | --- |
| `sdk/object` | Object references, Map/List containers, tagged structs, and recursive child-first Commit |
| `sdk/authentication` | Queries, independent verification, immutable writers, bounded sessions, and candidate batches |
| `sdk/authentication/builtin` | Optional verification-only KZG and IPA engines |
| `engine` | Apply Root-selected derivation and combine the tree with commitment capabilities |
| `derivation` | Deterministic conversion of application label bytes to coordinates |
| `auth/coordinate` | Coordinate types and canonical key/index encodings |
| `auth/tree` | Coordinate-only Prefix/Positional construction, updates, and proofs |
| `auth/commitment` | Separate commitment, proving, and verification capabilities; KZG and IPA backends |
| `auth/arcset/materializer` | Narrow injected lookup/update/snapshot capabilities and an in-memory reference implementation |
| `traversal` | Compose explicit authenticated steps across Roots |
| `maltcid` | Root descriptors, exact commitment profile identities, and CID/node encoding |
| `protocol` | Serialized contracts, strict runtime decoding and validation, and JSON schemas |

Core owns no durable ArcTable, KV/CAS backend, HTTP server, or application path
policy. [Gateway](https://github.com/DeWebProtocol/gateway) owns managed services,
persistence, and publication. The [local MALT runtime](https://github.com/DeWebProtocol/malt)
owns UnixFS, trusted roots, payload binding, and CLI/daemon behavior.
[malt-ts](https://github.com/DeWebProtocol/malt-ts) owns browser integration;
[malt-evaluation](https://github.com/DeWebProtocol/malt-evaluation) owns reproducible
measurements.

## Read flow

1. The client selects a Root and builds `AuthenticationRequest`.
2. An executor calls `authentication.Execute` or `ExecuteWithRoots` against
   caller-owned node lookup capabilities.
3. `authentication.Verify` checks the exact request, ordered traversal, final
   operation, and all openings locally.
4. A consuming application binds any returned bytes to their authenticated
   CIDs and applies its own trust/freshness policy.

The query profile is `malt.authentication/3`. It supports explicit resolution,
a final binding query, or a fixed-chunk Positional byte range. Missing traversal
steps carry authenticated early termination; the unevaluated suffix is not
claimed to be absent. See [query contracts](docs/spec/authentication-contracts.md).

Within one binding or range query, the tree loads each touched node once,
prepares its opening material once when the profile supports preparation, and
reuses only locally verified index evidence. This work is scoped to that call;
returned proofs own their buffers, and a later query checks its own materializer.

## Write flow

`sdk/object` is an optional construction layer above the authentication SDK.
Each Object is an application vertex: raw Immutable leaves return content CIDs,
while authenticated containers return MALT Roots. Map keys, List indices and
explicit struct tags describe references. Recursive Commit resolves child CIDs
before constructing the parent ArcSet and retains a writer on each authenticated
object. No object-specific encoding or payload-name interpretation enters
`auth/tree`. See the [Object guide](docs/guides/objects.md) for the API, payload
convention, complete example, and retention boundaries.

`BuildWriter` constructs a new immutable ArcSet. `NewWriter` validates and owns
a complete imported candidate. `Apply` checks expected-before bindings and
copies changed paths while sharing immutable descendants. `Update` scans a
complete desired state to derive that delta. `Root` is cheap; `Export` is an
explicit complete input/node traversal. New or externally supplied nodes are
validated, while unchanged owned nodes need no repeated commitment check.

`Session` bounds retained branches by handle count and conservative state
charge. Handles are local capabilities, never Roots, receipts, or trust
statements. Discard and clear release branches; stale handle IDs are not reused.
The transport-neutral `sdk/authentication/host` exposes serialization and session
operations. The WASM ABI in `malt-ts` uses this same Go implementation without a
second writer state machine.

Applications update child ArcSets before rebinding parents and submit an
ordered `AuthenticationBatch`. The Core verifier validates each candidate and
its reachable node set. An `AuthenticationReceipt` binds the exact transaction,
base, final Root, normalized batch digest, and declared durability boundary.
It acknowledges materialization only. There is no portable transition proof,
authorization decision, publication action, or trusted-root promotion here.
See [batches](docs/spec/authentication-batches.md).

## Storage capabilities

Tree algorithms use `materializer.NodeLookup` and `NodeUpdater`. The encoded
adapter projects node references into narrow `Lookup`/`Updater` ArcSet ports;
`NodeStore` composes those two capabilities where both are needed. Snapshot and
iteration remain separate capabilities. There is no aggregate compatibility
`Store`, `MutableStore`, or `BranchingStore` API.

The reference in-memory ArcSet store retains snapshots and node ownership for
callers that exercise those ports. It has no root-retention or reachability-GC
policy. SDK sessions retain immutable tree materializations directly and apply
their own handle and memory limits.

Physical node identity is layout/profile qualified and independent of input
preimages. Complete outer Roots retain their derivation profile. Caller-owned stores
may share identical immutable vectors but must not conflate query semantics or
use commitment equality as interchangeable Root identity.

Core defines no ArcTable/KV/CAS persistence, transactions, HTTP, recovery
records, UnixFS, managed account, authoritative head, or trusted-root policy.
Those belong to Gateway and the local runtime. Architecture tests enforce the
import direction and prevent restoration of retired packages.

## Portable boundary

`sdk/authentication/builtin` constructs verification-only KZG/IPA profiles.
Backend-specific writers inject their selected implementation without importing
the other backend. `malt-ts` owns all WASM entrypoints, compilation, browser
initialization, integration runners, release archives, and the stable TypeScript
API. It builds against an exact published Core source release and consumes the
portable corpus from `conformance/`; Core remains normative for semantics and
provides no WASM build or distribution targets.

`conformance/internal/generate` deterministically generates the portable corpus
used by native and WASM verification. Its regeneration entrypoint is
`conformance/cmd/generate`; neither package belongs to the runtime dependency
graph.

# MALT Core Architecture

MALT Core is an application-neutral authentication SDK. Correctness is relative
to the full caller-selected Root and typed query. Materializers and remote
executors supply untrusted data; they do not select the client's trust anchor.

## Layering

```text
derivation -> auth/coordinate -> auth/tree -> auth/commitment
                    engine binds coordinate derivation to the Root
                    traversal composes explicit steps across Roots
                    sdk/authentication supplies queries and retained writers
                    protocol / wire define their serialized contracts
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

Authentication layout means Prefix or Positional organization within one
authentication tree. ArcSet organization means how an application distributes
bindings across Roots: flat, compositional, or mixed. ArcSet organization is
not encoded in the Root.

A slash inside a label is data. Traversal steps are explicit application labels and
cannot be regrouped, inferred by longest-prefix search, or extended by a
hidden payload redirect. Application ArcSet organization remains
outside the tree. Applications choose any payload label explicitly and own reserved-name policy.

Applications currently assume a single valid resolution chain. This is a
construction assumption; traversal evidence does not prove uniqueness. A
longest-match search is an outer traversal strategy, not a maximality claim
attached to these explicit binding proofs.

`commitment.Committer`, `Prover`, and `Verifier` are independent capabilities.
The profile registry records identity and capacity; individual operations require
only their relevant capabilities. Both KZG and IPA expose verification-only types
without execution methods. The SDK stays backend-neutral; `builtin.NewVerifier`
is an opt-in constructor that imports the built-in verification implementations.

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

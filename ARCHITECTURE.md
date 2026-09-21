# MALT Core Architecture

MALT Core is an application-neutral authentication SDK. Correctness is relative
to the full caller-selected Root and typed query. Materializers and remote
executors supply untrusted data; they do not select the client's trust anchor.

## Layering

```text
auth/input -> auth/coordinate -> auth/tree -> auth/commitment
                    auth/engine binds input interpretation to the Root
                    traversal composes explicit steps across Roots
                    sdk/authentication supplies queries and retained writers
                    protocol / wire define their serialized contracts
```

`auth/tree` owns canonical Prefix/Positional node construction, affected-path
updates, snapshots, and binding/range evidence. It receives coordinates and
installed exact VC profiles and operation-specific capabilities; it knows no label grammar, application graph, payload
selector, or persistent store policy. `auth/engine` applies the Root's input
rule before entering the tree. Every traversal hop uses the descriptor of the
Root reached by the preceding authenticated binding.

A slash inside a label is data. Traversal steps are explicit typed inputs and
cannot be regrouped, inferred by longest-prefix search, or extended by a
hidden payload redirect. Application flat/hybrid/rooted organization remains
outside the tree. A rooted payload read supplies the system payload selector
at the reached Prefix; a flat relation may already target a payload/manifest.

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

The query profile is `malt.authentication/1`. It supports explicit resolution,
a final binding query, or a fixed-chunk Positional byte range. Missing traversal
steps carry authenticated early termination; the unevaluated suffix is not
claimed to be absent. See [query contracts](docs/spec/authentication-contracts.md).

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

Physical node identity is layout/profile qualified and independent of input
preimages. Complete outer Roots retain their input rule. Caller-owned stores
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

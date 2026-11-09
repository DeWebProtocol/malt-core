# Map/List VC Trees and retained writers

The current authentication tree lives in `auth/tree`. Map (`L=1`) authenticates
exact original label bytes and target CIDs, using derived coordinates for routing.
List (`L=2`) authenticates dense integer indices and root count metadata. Both
compose vector commitments into immutable trees. The application-facing
`sdk/object` containers consume these layouts; they do not define them.

Map construction, cell encoding and routing live in `map.go`, with updates in
`map_update.go`. List geometry and cell encoding live in `list.go`, with
replacement, append, truncation and payload changes in `list_update.go`.
`engine` binds derivation/layout/exact VC profiles to complete Roots;
`traversal` composes explicit steps across Roots.

## State lifetime

`authentication.BuildWriter` constructs immutable state; `NewWriter` validates
an imported complete candidate. `Apply` copies changed paths and shares unchanged
descendants. `Update` compiles a complete desired state to the same delta path.
List `AppendBatch` commits each affected vector once for the complete suffix.
A resulting writer retains no obsolete parent-writer chain.

`Root` returns the candidate identity. `State` copies labels and targets;
`Export` also traverses complete reachable nodes. New external materialization
is checked against its commitments. Owned unchanged vectors do not repeat that
check. Returned buffers are detached. Bounded snapshots check each distinct
vector once, but count every logical binding toward the expansion limit.

Sessions bound retained branches by handle count and conservative state charge.
Discard/clear releases branches; stale handles are not reused. Retained state
is local computation, not a portable transition proof or client trust decision.

## Current framing and diagnostics

Roots use V=0 with Map=1 and List=2. Their descriptors select the layout, exact
VC/backend profile and label-to-coordinate derivation profile; the identity
multihash carries the multicommitment directly. Internal references retain
`"MN" || 0x00 || byte(L) || multicommitment`. Historical experimental data is
outside the supported data set and adds no fields to the current format.

Core has no observation package or timing callbacks. Gateway and Evaluation
wrap the injected node and VC capabilities to measure their own operations.
See the [Root/layout specification](../spec/authentication-inputs.md),
[query contracts](../spec/authentication-contracts.md), and
[candidates/batches](../spec/authentication-batches.md).

`sdk/authentication/host` shares native/WASM serialization and bounded sessions.
`malt-ts` owns WASM entrypoints, browser Workers and exact published-Core assets.

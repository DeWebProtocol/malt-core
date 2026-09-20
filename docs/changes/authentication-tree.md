# Independent authentication tree and retained writers

Typed authentication now has one coordinate-only tree implementation in
`auth/tree`. `auth/input` derives coordinates defined by `auth/coordinate`;
`auth/engine` binds that interpretation to the full Root descriptor. The engine
re-exports the tree's shared result types for its typed API; there is no second
proof representation or historical-format decoder behind those names.

The tree owns Prefix and Positional construction, canonical cell encoding,
affected-path updates, complete bounded snapshots, and binding/range proofs.
It consumes narrow node capabilities and installed exact VC profiles. It does
not interpret labels, payload selectors, application graphs, relation versions,
or storage policy. `graph/traversal` owns explicit typed traversal across Roots,
including lazy Root-scoped lookup used by `sdk/authentication`.

## Source migration

Typed cross-Root proof values now use `graph/traversal.Traversal` instead of
`engine.Traversal`. Register exact commitment backends through the registry
passed to `engine.New`, or through `engine.Tree.Profiles` when configuring an
existing facade. The former `engine.Profiles` field is no longer a second
configuration surface. Downstream source callers, including tests, must migrate
these references when adopting the new Core release.

## State lifetime and incremental work

`authentication.BuildWriter` builds owned immutable state directly.
`authentication.NewWriter` validates a complete imported candidate before
retaining it. `Writer.Apply` accepts a typed `Delta`, copies affected paths in
both the input index and authentication DAG, and shares unchanged descendants.
The resulting writer retains no parent writer or obsolete ancestor chain.
`Writer.Update` scans complete desired inputs and compiles them to the same delta
path; callers that already know their changes use `Apply` to avoid that scan.

`Writer.Root` returns the candidate identity without exporting state.
`Writer.Export` explicitly traverses and copies complete inputs and nodes.
`Candidate` is the synchronous complete-export convenience. Neither updating
nor exporting owned vectors repeats their cryptographic validation. Untrusted
imports and external node writes still validate commitments; newly constructed
nodes are retained only through the tree's private computed-node path. Wrapping
an owned materializer does not grant this private capability. External readers
and writers receive detached node references and cannot mutate the commitment
being constructed or verified.

An `authentication.Session` retains bounded immutable branches. Its defaults are
64 handles and a 64 MiB conservative state charge. Shared descendants count at
each reference/candidate; this charge is not an allocator measurement. Failed
updates or capacity checks preserve existing handles. Discard/clear release
branches, and clear never reuses a stale handle identifier.

These are retained-state optimizations. Complete cold import/recovery remains
required; there is no partial witness protocol or node-internal incremental
commitment arithmetic. An exported candidate or local handle is not a portable
transition proof, publication receipt, or client trust decision.

## Payload queries and removed code

The caller's application schema supplies every typed query step. A rooted
content query can end with `Sys(Payload)` at the reached Prefix Root. A flat
path binding can point directly to a content/manifest CID. The flat entry Root
can still expose its own manifest through a system binding. Positional and
native-key profiles do not gain system payload support, and the literal label
`"@payload"` remains distinct from the system selector.

The old string resolver's implicit terminal redirect and `VerifyTranscript`
entry point are removed. Its current `ResolveKey` port continues to serve
explicit relation queries; typed payload composition uses the caller-bound
portable verifier. Unimplemented implicit/HAMT evidence and unused ProofList
kinds, commitment path extraction/cache constants, and obsolete node-geometry
algorithms are removed. The width adapter remains because Gateway uses it.

## Shared hosts and browser integration

`sdk/writer/host` owns transport-neutral serialization and bounded session,
checkpoint, candidate and receipt coordination previously duplicated in Core
and malt-ts WASM commands. Both commands retain backend selection and JS ABI
registration. The retained authentication ABI exposes create/import, delta
apply, complete export, discard and clear; the browser Worker serializes these
stateful operations. A ready Worker must provide the complete current ABI.

Root V=0, canonical tree nodes, and existing binding/resolve/read proof profiles
are unchanged. `malt.authentication-delta/0` is a new explicit retained-writer
input contract, documented in `protocol/schemas/authentication-delta.schema.json`.
The frozen authentication corpus remains unchanged. Native and WASM regression
coverage compares incremental Roots with fresh construction, verifies exported
candidates independently, rejects mutated materializers and omitted terminal
proof steps, and checks session bounds and handle lifetime.

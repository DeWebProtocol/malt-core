# Semantic Model

MALT's core semantic model authenticates graph arcs independently from immutable
CAS payload objects. Current typed arc coordinates are expressed through map
and list semantics, and vector-commitment backends authenticate the resulting
relations. This document is the implementation-bound terminology reference.

## Status

Experimental and implementation-bound. Public names may still change before a
stable release, but new docs should use this terminology.

## Core Terms

| Term | Meaning |
| --- | --- |
| Semantic object | A typed authenticated structure object, currently a map root or list root. |
| Graph root | A caller-supplied MALT structure root used as the verification handle for a read or mutation. |
| Arc query | A typed coordinate selecting one authenticated relation, currently `map_key`, `list_index`, or `list_range`. |
| Payload | Immutable application bytes or metadata stored as ordinary CAS content and bound from MALT structure. |
| Outgoing arc | A canonical coordinate-to-CID binding represented in an arc set. |
| Map relation | A key/path-like authenticated binding from a map object to a target CID. |
| List child reference | An index-addressed authenticated binding from a list object to a child CID. |
| CAS blob | Immutable content-addressed bytes outside the MALT semantic layer. |

The implementation uses `auth/arcset` for canonical arc and coordinate
representations. Runtime materialization may use bucket or namespace keys
internally, but those storage keys are not semantic coordinates.

## Map Semantics

Map semantics authenticate key-to-CID relations. The current public abstraction
lives in `auth/semantic/mapping`, and the primary SDK implementation lives
under `auth/semantic/mapping/radix`.

Native map operations are:

- exact key lookup with binding proof
- insert, replace, and delete of canonical keyed bindings
- commitment and verification of committed map state

`@payload` is the standard reserved coordinate for a terminal application-payload
binding. Generic maps may omit it; relation-only maps without a payload binding
are valid MALT state. When present, `@payload` must use terminal
`payload_binding` proof semantics. The UnixFS application model requires the coordinate
for its file and directory objects.

## List Semantics

List semantics authenticate ordered child references. The current public
abstraction lives in `auth/semantic/list`, and the primary SDK implementation
lives under `auth/semantic/list/tree`.

Native list operations are:

- index lookup with proof
- append
- replace existing index
- truncate
- optional measured range proof when the implementation authenticates byte
  layout metadata

List objects do not auto-redirect through `@payload`, and list reads do not own
path-resolution semantics. Application/client adapters translate file ranges or domain
queries into list index or measured-range reads.

The current measured-list implementation is fixed-width. It authenticates child
count, total size, chunk size, index-to-CID bindings, and the selected byte
range's covered segment CIDs. A future variable-size measured list remains a
proposal-stage topic in [MIP-1006](../mips/mip-1006-variable-size-measured-list-evidence.md).

## Typed Core Facade

The module-root `package malt` exposes the application-neutral `v0alpha1`
facade:

- `ResolveRequest` binds canonical segments to a caller-supplied root.
- `ResolveResult` carries the resolved target and ordered ProofList.
- `Resolver` and package-level `VerifyResolve` separate untrusted path
  execution from the client trust decision.
- `Query` selects one primitive map key, list index, or measured-list range.
- `ReadRequest` binds a typed query to a caller-supplied root.
- `ReadResult` carries the target, optional ordered range segments, and
  ProofList.
- `Mutation` and `WriteResult` project the namespace-free contracts from
  package `mutation`.
- package-level `VerifyRead` binds the request and result before portable proof
  verification.
- `execution.Executor.Resolve`, `Read`, and `Apply` are the separate, untrusted
  execution facade.

Map `Prove` returns either a membership binding or a root-bound non-membership
binding (`Present=false`). Radix non-membership terminates at an authenticated
empty slot, a conflicting leaf, or a collision bucket whose complete canonical
vector (including empty tail slots) is batch-opened. `execution.Executor.Read`
keeps its established application contract: it converts an absent binding, or
the compatibility sentinel `mapping.ErrPathNotFound`, into an error recognizable
through `errors.Is(err, malt.ErrQueryNotFound)` or `malt.IsQueryNotFound`. Other
execution-plane errors are returned unchanged.

Client/application adapters compose primitive arc operations into domain
traversal. A Unix path is therefore a UnixFS client concern, not a generic core
query requirement.

## Resolver And Writer Ports

The `graph` package is a small port/composition surface, not a separate
semantic owner.

- resolver is the read/proof port: `(root, query) -> result + ProofList`
- writer is an execution port: `Apply(baseRoot, semantic mutation) -> newRoot + receipt`
- `graph.StructureCreator` is the separate no-base-root bootstrap capability

Resolver traversal lives under `graph/resolver`. Mutation application lives
under `graph/writer`. These are SDK execution algorithms, not transport
contracts. Client/application adapters translate source-domain data into
queries and mutations; they do not redefine map or list semantics.

The portable verification path lives under `auth/verifier` and `sdk/verifier`.
It does not depend on resolver, writer, materializer, ArcTable, CAS,
application model, server, or gateway state.

## ArcSet Materialization Boundary

Core proof-generation algorithms consume the narrowest required capability
from `auth/arcset/materializer`: `Lookup`, `Updater`, `NodeStore`, or
`MutableStore`. The full `Store` aggregate is adapter compatibility, not the
default algorithm dependency. These capabilities load and materialize ArcSet
views and internal commitment nodes without defining persistence or ArcTable
semantics. ArcTable/KV implementations belong to executors such as the managed
gateway. Incorrect materialized state should either fail proof generation or
produce evidence that the portable verifier rejects.

Freshness, head publication, merge policy, CAS availability, pinning, garbage
collection, tenant isolation, and quotas are deployment or application policy,
not core MALT semantics.

## Related Proposals

- [MIP-1001](../mips/mip-1001-semantic-object-and-arc-terminology.md) tracks
  terminology adoption.
- [MIP-1010](../mips/mip-1010-data-authentication-core-boundary.md) records the
  historical package-boundary split.
- [MIP-1011](../mips/mip-1011-arc-authentication-core-contract.md) defines the
  portable arc-authentication contract and root-package facade.

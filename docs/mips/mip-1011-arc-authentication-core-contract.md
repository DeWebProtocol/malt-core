---
mip: 1011
title: Arc Authentication Core Contract
description: Define MALT as a portable arc-granularity graph data-authentication system with typed read, mutation, and verification contracts.
author: MALT maintainers
status: Final
type: Standards Track
category: Core
created: 2026-07-11
requires: 1001, 1003, 1010
replaces: none
---

## Abstract

MALT is a general graph data-authentication system whose authentication
granularity is an arc rather than a storage block. Application payload bytes
remain ordinary immutable objects in content-addressed storage (CAS), while
vector-commitment (VC) backends commit to and prove typed relations. UnixFS is
one application model/profile over this core; it is not the definition of MALT.

This MIP defines the public core contract introduced in `v0.0.3`: a portable,
trusted authentication kernel; an untrusted execution engine; typed
`Read`/`Apply`/`VerifyRead` operations in the module-root `malt` package; and an
experimental ProofList artifact profile named `v0alpha1`.

> **Boundary update:** MIP-1013 preserves these typed contracts while moving
> proof generation and mutation application to `execution.Executor`, leaving
> package-level `VerifyRead` in the root facade. It also replaces the old
> `layout/unixfs` ownership with model/client/runtime packages.

## Motivation

In a Merkle DAG, a child relation is normally an implicit arc encoded inside a
parent block. The parent CID simultaneously identifies the serialized parent,
authenticates its embedded links, and makes the linked block chain the natural
traversal and proof path. The authentication granularity is therefore the
block. Changing one embedded relation can change ancestor CIDs, and an
application must understand the DAG layout to read and verify the result.

MALT separates three concerns that an implicit arc couples:

1. **Payload storage:** immutable bytes keep ordinary CIDs and live in CAS.
2. **Relation authentication:** a typed arc is committed and proved by a VC
   backend under a MALT root.
3. **Execution and access:** indexes, ArcTable materialization, caches,
   reference executors, gateways, and application adapters locate or serve the
   relation and its proof.

This separation permits direct application-shaped queries without making the
payload block the proof carrier. It also permits execution-plane optimizations
without adding them to the correctness trust boundary. The performance claims
remain workload- and backend-dependent and must be supported by the repository
evaluation suites; the contract itself does not promise constant end-to-end
latency or free updates.

## Specification

### System Scope

The MALT core authenticates graph-shaped relations:

```text
trusted root + typed arc query
              |
              v
       target + ProofList
              |
              v
     portable verification
```

The current semantic vocabulary includes keyed map relations, stable list
indexes, and measured-list ranges. Future semantics may add other typed arc
coordinates without changing the separation between payload, authentication,
and execution.

CAS is the payload backend. VC schemes are the commitment and proof backends.
Neither choice makes UnixFS, an HTTP route, an executor, or ArcTable part of the
abstract data model.

### Trusted Authentication Kernel

The trusted kernel contains only code and data needed to validate an answer
relative to caller-supplied trusted inputs:

- canonical arc coordinates and arc sets
- typed root and canonical commitment-input rules
- map/list proof semantics
- commitment verification backends
- ProofList shape, ordering, query, target, and evidence verification

The portable verifier lives under `auth/verifier`. Its verification path must
not require ArcTable, CAS access, a graph runtime, an application model, an HTTP
server, or executor state. The built-in registry may select KZG or IPA verification from a
typed MALT root; integrations may provide compatible verification-only
backends through the narrow verifier interfaces.

The caller supplies the trusted root and expected typed query. Verification
must bind the query kind and coordinate to the primitive proof step, as well as
the returned target and, for measured ranges, the ordered segment CIDs. A proof
that is cryptographically valid for a different root, query kind, coordinate,
target, or range result must not be accepted.

### Untrusted Execution Engine

The execution plane may generate proofs, apply mutations, cache state, and
serve results. It includes:

- concrete map/list semantic implementations used for proof generation and
  mutation
- ArcTable and other materialized indexes
- storage and cache adapters
- resolver and writer orchestration
- reference executors and HTTP servers
- managed gateways

These components can affect availability, latency, and which candidate result
is returned. They do not decide correctness. A client accepts a read only after
the portable authentication kernel verifies it against the client's trusted
root and query.

ArcTable is specifically outside the trust boundary. It is reusable execution
state, not a commitment backend, a canonical graph representation, or an
authority for the current root.

### Module-Root Facade

The module-root `package malt` is the application-neutral integration facade.
Its `v0alpha1` contract exposes:

- `Query`, with `map_key`, `list_index`, and `list_range` kinds
- `ReadRequest`, binding a caller-supplied root to one typed query
- `ReadResult`, carrying the authenticated target, optional range segments,
  and ProofList
- `Mutation` and `WriteResult` aliases for the current semantic mutation and
  result-root receipt
- package-level `VerifyRead`
- portable `Mutation` and `WriteResult` projections from package `mutation`

Conceptually:

```text
execution.Executor.Read(ReadRequest{Root, Query}) -> ReadResult{Target, Segments, ProofList}
execution.Executor.Apply(Mutation{BaseRoot, ...})  -> WriteResult{NewRoot, ...}
VerifyRead(request, result)                         -> nil / error
```

`execution.Executor` composes execution-plane implementations and supplies an
operational scope so placement does not leak into canonical requests or
mutations. It deliberately does not own a verifier or trust decision;
`VerifyRead` is called separately by the client.

One `Query` represents one primitive typed arc operation. Layouts and
applications compose primitive reads when their domain operation requires
multi-step traversal. The core facade does not standardize a Unix path policy,
directory manifest, HTTP response, or latest-head service.

MIP-1012 extends this boundary in `v0.0.4` with an application-neutral segment
array and proof-carrying multi-arc resolution. It does not add Unix, URL, or
language-object parsing to core and does not change the primitive `Query`
contract defined here.

### Reserved `@payload` Coordinate

`@payload` is the standard reserved coordinate for binding a semantic object to
its application payload. Reservation means that application models and generic applications
must not assign conflicting semantics to that coordinate.

It is not mandatory for every generic map. A relation-only map with no payload
binding is valid MALT state. When `@payload` is present, its proof step uses the
terminal `payload_binding` semantics and traversal must not continue through it
as if it were an ordinary relation.

The UnixFS model requires `@payload` for its file and directory objects. That
requirement belongs to the UnixFS client model, not to generic map semantics. Other
models may require the coordinate, omit it, or define additional reserved
coordinates while preserving the core rules.

### UnixFS Application Boundary

UnixFS is the first broadly used application model over MALT. It maps
file and directory operations to generic map/list relations and keeps file
bytes or chunks in CAS.

UnixFS-specific behavior includes:

- path parsing and directory traversal
- mandatory `@payload` bindings
- small-file raw payloads and large-file list roots
- byte-range body binding
- file and directory mutation planning

As of v0.0.6, these responsibilities live in the independent
`DeWebProtocol/malt-client` repository and the browser client. Neither these
capabilities nor the UnixFS data model become requirements for a future Pod,
protocol, agent-memory, manifest, or other graph application.

### Proof Artifact Profile

The current verifier-facing artifact profile is `v0alpha1`. It consists of the
current `auth/proof/prooflist.ProofList` envelope and the typed
`Query`/`ReadRequest`/`ReadResult` binding rules defined by this MIP and the
[ProofList format](https://github.com/dewebprotocol/malt-core/blob/a4526f8751db403eaa2e1a7ac6add00b70ff2933/docs/spec/prooflist-format.md).

`v0alpha1` is a contract profile, not a stability promise. The current JSON
envelope does not carry an embedded version discriminator and does not yet have
a stable named JSON Schema. Consumers must pin the MALT module or source
release. A later MIP may add explicit wire version negotiation or promote a
machine-readable schema without treating the current shape as stable.

MIP-1004 later publishes `malt.artifact/v0alpha2` as a separate explicit
cross-process envelope around resolve, primitive prove, and verify. The
original `v0alpha1` facade described here remains the in-process primitive
binding baseline.

### Import Direction

The implementation should maintain this ownership direction:

```text
auth kernel <- module-root malt + mutation <- clients / applications
                         ^
                         |
              execution <- graph + runtime
```

Normative dependency constraints are:

- `auth/**` must not import graph runtime, ArcTable, storage, application,
  server, or executor packages.
- the portable `auth/verifier` must perform no runtime or storage lookup.
- `graph/**` may consume authentication contracts but must not own concrete
  runtime storage.
- model/client adapters may consume core value types and narrow payload
  capabilities, but must not redefine proof or root semantics.
- server and reference-executor packages are adapters over the same contracts, not the
  integration API for a managed gateway.

The repository remains one Go module for `v0.0.3`. This MIP does not require a
new repository or nested Go module for the kernel.

## Security Considerations

MALT proves inclusion or binding relative to a trusted root. It does not decide
that a root is fresh, authoritative, globally latest, or authorized for a
particular user. Root publication, rollback prevention, multi-writer policy,
identity, authorization, availability, retention, and billing remain
application or gateway responsibilities.

CAS CIDs authenticate fetched payload bytes, while MALT proofs authenticate
the relation from a trusted MALT root to the payload CID. Applications that
accept returned body bytes must perform both checks. UnixFS range responses
also require the range-body binding described in the ProofList specification.

## Compatibility

All facade names, ProofList fields, query labels, root codecs, and verification
interfaces described here remain experimental before `v1.0.0`. `v0.0.3` is a
source release for experimental integrators, not a stable API guarantee.

MIP-1010 remains the historical record of the repository package split. This
MIP defines the subsequent public arc-authentication contract; it does not
reverse the ownership boundaries established by MIP-1010.

## Release Record

This contract was validated first as `v0.0.3-rc.1`, then published from the
same approved source commit as `v0.0.3` after repository, external-consumer,
evaluator, and CLI proof smokes passed.

`v0.0.3-core-boundary` may remain in historical milestone or planning text, but
it is not a valid final release tag for this contract.

## Review Checklist

- The root `malt` facade compiles for an application that does not import
  `server` or `runtime` packages directly.
- Portable proof verification runs without CAS, ArcTable, daemon, or network
  access.
- A non-UnixFS relation-only map can be created without `@payload`.
- UnixFS still requires and verifies its `@payload` bindings.
- ArcTable and concrete runtime/storage packages do not enter the auth kernel's
  production import graph.
- Proof tampering, query mismatch, target mismatch, and range-segment mismatch
  are rejected.
- Full tests, vet, command builds, evaluator smoke, and an external consumer
  compile/run smoke pass before tagging.

## History

- 2026-07-11: Implemented the portable facade and authentication kernel in PR
  #159.
- 2026-07-12: Hardened typed-root and malformed KZG proof handling in PR #160,
  completed release validation, and finalized the contract for `v0.0.3`.

## References

- [MIP-1010: Data Authentication Core Boundary](./mip-1010-data-authentication-core-boundary.md)
- [Semantic model](https://github.com/dewebprotocol/malt-core/blob/a4526f8751db403eaa2e1a7ac6add00b70ff2933/docs/spec/semantic.md)
- [ProofList format](https://github.com/dewebprotocol/malt-core/blob/a4526f8751db403eaa2e1a7ac6add00b70ff2933/docs/spec/prooflist-format.md)
- [Commitment model](../spec/commitment.md)
- [v0.0.3 release notes](../releases/v0.0.3.md)

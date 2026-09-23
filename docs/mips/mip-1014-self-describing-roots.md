---
mip: 1014
title: Self-Describing Roots and Authentication Inputs
description: Assess the Root, key, layout, proof, and writer changes needed for self-describing authentication.
author: MALT maintainers
status: Draft
type: Standards Track
category: Core
created: 2026-09-12
requires: 1011, 1012, 1013
replaces: none
---

## Abstract

Separate MALT input interpretation and authentication layout from the complete
VC profile identifying a commitment. This draft records the proposed boundary
and source-inspected refactor scope. The maintainer has separately fixed the
[Root version policy](../policy/root-versioning.md): pre-production Roots use
`V=0`, and only an explicit production-ready declaration permits `V=1`.
The experimental implementation and exact framing now live in the
[Root/input specification](../spec/authentication-inputs.md). This MIP remains
Draft pending review and coordinated downstream adoption.

## Motivation

Before this refactor, `wire/maltcid` encoded version, Map/List semantics, and KZG/IPA backend
in `0x30VSBB`. Radix construction and verification hash canonical paths and
authenticate the original path in terminal markers. Backend registration
selects one configuration per broad algorithm kind. These interfaces do not
yet express direct native keys, Root-selected label rules, or several VC
parameter profiles from the same algorithm family.

## Specification

The proposed codec notation is `0x30VLAA`: `V` selects the MALT Root format,
`L` selects Positional/Prefix authentication interpretation, and `AA` selects
an input rule. A multicommitment identifies the exact VC profile and carries
the commitment. The preferred container under review remains CIDv1 with an
identity multihash containing that multicommitment. The reference specification now defines experimental IDs and canonical byte framing.

Positional/direct consumes a canonical integer index. Prefix/direct consumes
a native byte key under an explicit key-width rule. Prefix/label consumes a
selector under a predefined rule covering encoding, namespace treatment,
derivation, output width, and conflicting bindings. Unsupported combinations
must be rejected. Key distribution must not select a layout heuristically.

Layout rules determine node/leaf encoding, empty and absent states, metadata,
routing, and valid proofs together with the selected VC profile. That profile
fixes algorithm parameters, parameter identity, capacity, commitment encoding,
and the required primitive verification rules. Cell to scalar conversion
needs a fixed owner. Runtime-only MSM/precomputation choices must not allocate
different cryptographic profiles.

The implementation fixes native keys at 32 bytes and indices at eight canonical
big-endian bytes. Opaque labels are derived outside auth using Direct (3) or
SHA256 (4); payload and UnixFS conventions belong to applications. Internal
nodes have derivation-independent identities. Exact multicommitment framing and rule IDs are
recorded in the reference specification. Future normative definitions belong in
[the reference specifications](../spec/README.md), with executable schemas
and conformance vectors in this repository.

## Rationale

The serial computation is input interpretation, authentication coordinates,
layout construction with VC computation, and Root encoding. Positional/Prefix
describe authentication organization more precisely at the Root boundary.
Existing Map/List convenience APIs may survive through adapters; dense
sequence and key-binding constraints still need exact definitions.

Keeping CIDv1 avoids replacing the common identifier container throughout
downstream systems. Bare codec plus multicommitment would require a new Root
container and transport/value adapters. The implementation uses this envelope.

## Backwards Compatibility

New construction targets `V=0`, not a bump from experimental `V=3`. Existing
flat and structured experimental Roots retain their original interpretations
and evidence identities. A migration must specify rejection, reconstruction,
or retained readers as described in the [version policy](../policy/root-versioning.md).

Root, leaf, and internal-node changes propagate into parent references,
materialization, update views, bundles, and caches. A prefix rewrite cannot
stand in for replay and reconstruction. Unchanged immutable payload CIDs can
be reused. Source packages, operation profiles, storage formats, and corpora
have independent versioning.

## Security Considerations

Verification uses the complete caller-selected Root descriptor and query.
Equal raw commitments are not equal Roots when interpretation differs.
Profile IDs must not select mutable parameters or fall back to defaults.
Prefix evidence binds the complete key and target; absence follows the new
leaf/collision rules. Retaining labels does not itself establish key isolation.
Native and portable verifiers must migrate together. Receipts and candidate
Roots remain operational outputs, not portable transition proofs.

## Implementation Plan

The maintainer authorized the opaque-label coordinate-derivation refactor. The following boundaries guide review
of the experimental change; they are not a production-readiness declaration.

| Candidate boundary | Current Core touchpoints | Necessary evidence |
| --- | --- | --- |
| Root and VC profiles | `wire/maltcid`, `auth/commitment`, `auth/verifier/registry.go`, `auth/semantic/nodegeometry` | Exact parameter dispatch; canonical framing; unknown/profile/length rejection; `V=0`; no old-format aliasing |
| Coordinates and layouts | `auth/arcset`, `auth/semantic/mapping/radix`, `auth/semantic/list/tree`, materializer capabilities | No label rehash for direct keys; selector isolation; full-key leaves and absence; sequence/metadata boundaries |
| Proof and query contracts | `auth/proof/prooflist`, `auth/verifier`, `graph/resolver`, `graph/runtime`, `protocol`, `sdk/verifier` | Caller query/Root binding; profile composition; native/portable parity; profiled schema migration |
| Mutation and writer state | `mutation`, `graph/writer`, `sdk/writer`, module-root facade | Verified base reconstruction; exact candidate; parent rebinding; view/checkpoint/materialization consistency |
| Conformance and distribution | `conformance`, package-local fixtures, WASM entry points and release checks | New corpus provenance; historical corpora unchanged; published downstream release adoption |

Gateway owns records, indexes, recovery, persistent caches, service composition,
and product E2E. The MALT runtime owns application query conversion, UnixFS and
payload behavior, transport adoption, and candidate versus accepted-root state.
`malt-ts` owns exact-Core WASM/package adoption; `malt-evaluation` owns adapters,
profiles, schemas, and new measurement provenance. These responsibilities must
not move into Core during refactoring.

Cryptographic arithmetic can be reused where parameters and encoding remain
unchanged. Exercise label/native-key equivalence before whole-product rollout,
then persisted-state recovery and writer/read integration. Heavy validation
follows workspace resource limits.

## History

- 2026-09-12: Recorded the proposal and requested impact assessment against
  Core `c90b4d35ec95003b14422546b777fbf9ada2b0c7`; linked the separately
  confirmed pre-production `V=0` and explicit production `V=1` gate.

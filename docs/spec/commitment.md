# Commitment Model

MALT uses vector-commitment (VC) backends to authenticate typed graph arcs.
The semantic layer chooses the coordinate and value representation; the
backend commits, proves, and verifies already-positioned values. Payload bytes
remain ordinary CAS objects and are not stored inside the VC backend.

## Status

Experimental and implementation-bound. Current in-tree backends are KZG and
IPA, with KZG used by the default prototype profile.

## Backend Boundary

Commitment backends own:

- commitment byte generation
- proof generation
- proof verification
- update primitives when a backend supports efficient local updates

They do not own:

- map key semantics
- list index or range semantics
- path resolution
- application models and client adapters
- ArcTable materialization
- head publication or freshness policy
- payload storage or retrieval

The public interfaces under `auth/commitment` separate three capabilities:

- `Committer` computes commitments and performs checked index-stable replacement.
- `Prover` generates single or batch proofs against a supplied commitment; it
  never recomputes that commitment.
- `Verifier` checks supplied evidence without loading materialization.

`Backend` composes all three for hosts that need them. `tree.Profile` identifies
an installed backend by exact profile and capacity, without requiring all three
capabilities. Construction requires a `Committer`; query execution requires a
`Prover` and `Verifier`; verification requires only a `Verifier`. Retained owned
updates need commitment computation, while imports and untrusted materialization
also require proof generation and verification.

Coordinate-based layouts live in `auth/tree`; `engine` supplies typed
coordinate derivation. `sdk/authentication` verifies explicit traversal and
primitive evidence using exact Root-selected profiles without runtime state.

## Primitive values and semantic Roots

`commitment.Value` is an immutable primitive commitment carrying an exact VC
profile and commitment bytes. It has no semantic layout, derivation profile, or CID
codec. Constructors reject unsupported profiles and incorrect widths.
`CommitmentBytes(profile)` checks the selected profile before returning bytes.

`engine` constructs a semantic Root only after selecting a descriptor.
Current [self-describing V0 Roots](./authentication-inputs.md) bind the layout,
derivation profile, and profile-qualified commitment. Existing-root operations select
the profile from that Root. A process default applies only to new construction.
Each step in a cross-root traversal performs its own profile selection.

Prefix leaves bind a derived key to target CID bytes. Positional leaves bind
a stable index to a target, with authenticated structural metadata in slot
zero. The former Map/List and flat binding-CID commitment wrappers are removed. See
[commitment and proof encoding](./commitment-proof-encoding.md).

## Root-bound proof generation

The built-in KZG and IPA backends implement `commitment.PreparedProver`.
`PrepareOpening` prepares an immutable witness for a caller-selected
primitive value without computing its commitment. Preparation does not
validate untrusted cells. The engine opens the selected coordinate, checks the
returned root and cell, then calls `VerifyIndex` exactly once before returning
the proof. A corrupt vector fails verification. Backends without the prepared
capability use `Prover.Prove(root, cells, index)` and verify its result against
the same selected root. There is no commit-and-prove fallback.

Public `Prover` methods still verify their own outputs. The engine
uses the prepared capability to avoid repeating that verification. Cache
ownership, lifetime, serialization, persistence, authorization, publication,
and trusted-root selection remain caller responsibilities.

## Related Proposals

- [MIP-1005](../mips/mip-1005-kzg-map-label-domain.md) records the accepted
  historical binding-CID slot decision.
- [MIP-1010](../mips/mip-1010-data-authentication-core-boundary.md) records the
  historical package-boundary decision that keeps commitment primitives inside
  the data-authentication core.
- [MIP-1011](../mips/mip-1011-arc-authentication-core-contract.md) defines the
  VC-backed portable arc-authentication boundary.

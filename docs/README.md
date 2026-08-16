# MALT Docs

This directory is the implementation-bound documentation surface for
`DeWebProtocol/malt`.

Use these documents as the source of truth for behavior that must stay aligned
with code, tests, schemas, and wire formats. Public
website pages in `DeWebProtocol/malt-web` may summarize this material, but they
should link back here for protocol, policy, and compatibility details.

Managed gateway service behavior, including tenancy, identity, authorization,
root publication, backend orchestration, S3/Filecoin/IPFS deployment policy,
quota, cache policy, and operations, belongs in `DeWebProtocol/gateway` or
private deployment overlays. Client/daemon and UnixFS behavior belongs in
`DeWebProtocol/malt-client`; this repository contains neither product layer.
Executable benchmark suites, evaluator plans, comparison adapters, and result
schemas live in `DeWebProtocol/malt-evaluation`; paper interpretation and
research narrative remain in `DeWebProtocol/documents`.

## Concepts

- [Concepts index](./concepts/README.md)
- [Data authentication background](./concepts/data-authentication.md)
- [Merkle DAG vs MALT](./concepts/merkle-dag-vs-malt.md)

## Policy

- [Threat model](./policy/threat-model.md)
- [Compatibility policy](./policy/compatibility.md)
- [Release process](./policy/releasing.md)
- [v0.0.7-rc.5 release notes](./releases/v0.0.7.md)
- [v0.0.6 release notes](./releases/v0.0.6.md)
- [v0.0.5 release notes](./releases/v0.0.5.md)
- [v0.0.4 release notes](./releases/v0.0.4.md)

## Evaluation

- [Evaluation ownership and migration](./evaluation.md)

## Specifications

- [Specification index](./spec/README.md)
- [Resolve and read contracts](./spec/resolve-read-contracts.md)
- [Client-root contract](./spec/client-root-contract.md)

## MALT Improvement Proposals

MALT Improvement Proposals live in [docs/mips](./mips/). MIPs are the review
path for semantic, verifier-facing, schema, and core algorithm
changes before they become implementation work.

MIPs should define the proposal boundary, motivation, decision, alternatives,
compatibility impact, security impact, and implementation planning state. Long
field lists, wire formats, and JSON schemas belong in the reference docs under
`spec/`, with MIPs linking to them.

The previous `documents/MIPs` mirror in the research-paper workspace was
removed after migration. New implementation-bound MIP work should happen here.

The current public-core contracts are
[MIP-1011: Arc Authentication Core Contract](./mips/mip-1011-arc-authentication-core-contract.md),
[MIP-1012: Segment Path Resolution](./mips/mip-1012-segment-path-resolution.md),
the final
[MIP-1013: Client, Gateway, And Core Responsibility Boundary](./mips/mip-1013-client-gateway-core-boundary.md),
the operation-specific resolve/read profiles introduced by that MIP,
`malt.map-proof/v0alpha1`, and the experimental
[client-root contract](./spec/client-root-contract.md) included in
v0.0.7-rc.1, together with the frozen v0.0.4
artifact compatibility profile recorded by
[MIP-1004](./mips/mip-1004-resolve-prooflist-artifact-schema.md).

## What Goes Where

- `concepts/` for reader-facing background, comparisons, and orientation
- `policy/` for stability, safety, and release policy
- `releases/` for source-release notes and validation records
- `spec/` for formal protocol and schema documents
- `mips/` for design proposals and process records

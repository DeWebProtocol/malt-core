# Specification

This folder holds implementation-bound protocol and schema documents.

These documents stay aligned with code, tests, and MIPs in this repository.
They are the reference layer for current behavior; MIPs propose or record
changes to this layer.

For reader-facing background on hash authentication, Merkle DAGs, and MALT's
positioning, start with [Concepts](../concepts/README.md). Keep normative
behavior, wire formats, and proof semantics in this folder.

The current transport-neutral proof-bearing contracts are
`malt.resolve/v0alpha1`, `malt.read/v0alpha1`, and
`malt.map-proof/v0alpha1`. The experimental client-root
contracts are `malt.update-view/v1`, `malt.semantic-intent/v1`,
`malt.client-root-bundle/v1`, `malt.client-root-materialization/v1`,
`malt.writer-compute-result/v2`, and `malt.materialization-receipt/v1`. The
client-root contracts are included in v0.0.7-rc.1. The v0.0.4
`malt.artifact/v0alpha2` profile
remains frozen for compatibility. See [MIP-1012](../mips/mip-1012-segment-path-resolution.md) and
[MIP-1013](../mips/mip-1013-client-gateway-core-boundary.md).

## Documents

- [Semantic model](./semantic.md)
- [ProofList format](./prooflist-format.md)
- [Writer receipts](./writer-receipts.md)
- [Resolve and read contracts](./resolve-read-contracts.md)
- [Client-root contract](./client-root-contract.md)
- [Language-neutral conformance corpora](./conformance-corpora.md)
- [Frozen artifact compatibility profile](./artifacts.md)
- [Segment paths and resolution](./segment-paths.md)
- [Commitment model](./commitment.md)
- [Commitment and proof encoding](./commitment-proof-encoding.md)
- [CID and wire format](./cid-and-wire-format.md)
- [Resolve/Read conformance corpus v2](./resolve-read-conformance-v2.md)
- [Frozen Resolve/Read conformance corpus v1](./resolve-read-conformance-v1.md)

## Protocol Schema Index

Every filename returned by `protocol.SchemaNames()` is indexed here:

<!-- schema-catalog:protocol:start -->
- [`client-root-bundle.schema.json`](../../protocol/schemas/client-root-bundle.schema.json)
- [`client-root-materialization.schema.json`](../../protocol/schemas/client-root-materialization.schema.json)
- [`map-proof-request.schema.json`](../../protocol/schemas/map-proof-request.schema.json)
- [`map-proof-result.schema.json`](../../protocol/schemas/map-proof-result.schema.json)
- [`map-proof-verification.schema.json`](../../protocol/schemas/map-proof-verification.schema.json)
- [`materialization-receipt.schema.json`](../../protocol/schemas/materialization-receipt.schema.json)
- [`prooflist.schema.json`](../../protocol/schemas/prooflist.schema.json)
- [`read-request.schema.json`](../../protocol/schemas/read-request.schema.json)
- [`read-result.schema.json`](../../protocol/schemas/read-result.schema.json)
- [`read-verification.schema.json`](../../protocol/schemas/read-verification.schema.json)
- [`resolve-request.schema.json`](../../protocol/schemas/resolve-request.schema.json)
- [`resolve-result.schema.json`](../../protocol/schemas/resolve-result.schema.json)
- [`resolve-verification.schema.json`](../../protocol/schemas/resolve-verification.schema.json)
- [`semantic-intent.schema.json`](../../protocol/schemas/semantic-intent.schema.json)
- [`update-view.schema.json`](../../protocol/schemas/update-view.schema.json)
- [`verification-result.schema.json`](../../protocol/schemas/verification-result.schema.json)
- [`writer-compute-result-v2.schema.json`](../../protocol/schemas/writer-compute-result-v2.schema.json)
- [`writer-compute-result.schema.json`](../../protocol/schemas/writer-compute-result.schema.json)
<!-- schema-catalog:protocol:end -->

## Notes

- `mips/` remains the proposal, decision, and process bucket. It should link to
  reference specs instead of duplicating long schema definitions.
- `policy/` holds compatibility, release, and threat-model policy.

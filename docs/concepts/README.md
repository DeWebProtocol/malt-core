# Concepts

This folder gives reader-facing background for MALT. These documents explain
why the project exists and how to compare it with hash, Merkle tree, and
Merkle-DAG authentication models.

Use these documents for orientation. Implementation-bound behavior, wire
formats, proof fields, HTTP headers, and compatibility rules remain in
[`docs/spec`](../spec/README.md) and [`docs/policy`](../policy/README.md).

## Start Here

- [Data authentication background](./data-authentication.md) explains how hash,
  Merkle tree, and Merkle-DAG authentication work, then introduces MALT's data
  authentication model.
- [Merkle DAG vs MALT](./merkle-dag-vs-malt.md) compares object-chain proofs,
  direct `root + path` reads, HTTP proof transport, and rewrite amplification.

## Mechanism References

After the conceptual overview, use the implementation-bound specs for exact
mechanics:

- [authentication model](../spec/authentication-inputs.md) for application labels, coordinate derivation, Roots, authentication layouts, and ArcSet organization.
- [typed query evidence](../spec/authentication-contracts.md) for proof steps, ordering,
  serialized evidence, and range evidence.
- [Core architecture](../../ARCHITECTURE.md) for why service routes,
  authentication, CORS, and daemon APIs remain outside MALT core.
- [Commitment model](../spec/commitment.md) for backend proof assumptions.
- [CID and wire format](../spec/cid-and-wire-format.md) for root encoding.

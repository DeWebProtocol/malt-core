# Writer Receipts

Writer receipts report the operational outcome of applying semantic mutations.
They help clients, APIs, and evaluations account for work, but they are not
correctness proofs.

## Status

Experimental and implementation-bound. Field names may still change before a
stable release.

## Library Receipt

`mutation.WriteReceipt` records:

| Field | Meaning |
| --- | --- |
| `BaseRoot` | Caller-supplied root for the mutation. |
| `NewRoot` | Root produced after applying semantic deltas. |
| `DeltaCount` | Number of semantic deltas applied. |
| `ArcCount` | Number of canonical arc changes applied. |

The writer does not publish authoritative heads, choose freshness, prove a
state transition, or merge concurrent roots. Applications decide whether to
accept, publish, or select a produced candidate root.

## Mutation And Execution Ports

Package `mutation` is the stable portable contract. It defines
`SemanticMutation`, `ArcSetDelta`, commit descriptors, validation, and
`WriteReceipt` without namespace or storage placement.

`execution.MutationApplier` is the untrusted execution port. It exposes
`Apply(ctx, namespace, mutation.SemanticMutation)` and returns a
`mutation.WriteReceipt` with the caller-supplied base root and produced result
root. `graph.MutationWriter` is the reference graph adapter over that contract.

`graph.StructureCreator` separately bootstraps a root when no authenticated
base exists. `RuntimeGraph.Writer()` returns only `MutationWriter`.
Historical root-consuming arc helpers and the `ReferenceWriter` capability
are removed; lookup and snapshots belong to the caller-owned materializer.

Transport projections and application-level diagnostic counts belong to the
gateway or client that exposes them. They are not verifier evidence unless
separately tied to a cryptographic proof.

## Accounting Boundary

Receipts can support:

- client progress reporting
- API diagnostics
- benchmark write accounting
- storage or indexing estimates when paired with explicit metrics

Receipts do not prove:

- payload availability
- freshness of the selected root
- correctness of an unverified read
- publication or merge policy
- that a delta correctly transformed the accepted base root into the returned
  candidate root

MALT does not currently define a delta/state-transition proof. Therefore write
receipts stay separate from the proof-bearing resolve/read contracts instead
of being placed in a generic artifact union.

## Related Proposals

- [MIP-1002](../mips/mip-1002-writer-receipt-accounting.md) tracks whether the
  current receipt fields should become a stable API and evaluation contract.

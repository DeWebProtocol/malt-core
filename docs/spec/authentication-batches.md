# Authentication candidates, batches, and receipts

Complete state uses `malt.authentication/0`. A candidate contains its exact
Root, original typed inputs and targets, descriptor, and complete reachable
node vectors. Optional `previous` records storage lineage. The query profile
is independently versioned as `malt.authentication/1`.

Structural JSON validation is not cryptographic validation.
`authentication.ValidateCandidate` checks a candidate against its Root before
external materialization. Missing, conflicting, unreachable, or inconsistent
nodes fail. New retained writers own validated immutable nodes; unchanged
owned nodes can be reused across branches without revalidating them.

`malt.authentication-delta/0` describes expected-before typed changes against
retained complete state. Prefix supports insertion, replacement, and deletion;
Positional supports replacement, append, and suffix truncation with explicit
count and measured total size. It is not a partial witness or transition proof.
Applications rebuild changed child ArcSets before rebinding their parents.

## Ordered batches

`malt.authentication-batch/0` contains `transaction_id`, `base`, `root`, and
`candidates`. Transaction IDs contain 1–128 ASCII letters, digits, `.`, `_`, or
`-`. A batch contains 1–4096 distinct candidate Roots and canonical Root strings.
Its final candidate must equal the declared final `root`.

Every candidate whose lineage base or target is another candidate in the batch
must follow that dependency. Duplicate Roots, forward references, and cycles
fail. Existing dependencies may be outside the batch; service policy decides
whether they are available in the selected scope. Bootstrap can include the
selected base as a newly constructed candidate. Core validates candidates and
order, while a service owns authorization, atomic persistence, idempotency,
lineage storage, durability guarantees, and publication.

`authentication.ValidateBatch` cryptographically verifies all candidates.
`AuthenticationBatch.Validate` checks structural shape/order only. A service
must not substitute the latter for the former on untrusted input.

The digest is SHA-256 over the UTF-8 batch profile, one zero byte, then the
normalized Go JSON projection of the entire batch. Candidate and entry order
are significant. Core hosts expose this calculation; adapters must not invent
a second canonical serializer or hash arbitrary incoming JSON bytes.

## Exact receipts and trust

`malt.authentication-receipt/0` carries `transaction_id`, `base`, `root`,
`digest`, and a nonempty `durable_boundary`. Receipt validation requires those
values to match the exact locally computed batch, including profile and digest.
A substituted candidate, reordered batch, transaction, base, or final Root
must fail. The durability boundary is a service assertion, not a signature.

An exact receipt may let an application advance its retained writer workflow.
It does not establish a portable state transition, authorization, freshness,
publication, content availability, or client-trusted Root. Accepted/candidate
Root policy remains with the client. A lost response must retain the same exact
batch for retry; recomputing another transaction is an application decision.

Schemas are `authentication-{state,candidate,delta,batch,receipt}.schema.json`.
The WASM/native shared host is `sdk/authentication/host`.

# Frozen `malt.artifact/v0alpha2` Compatibility Profile

`malt.artifact/v0alpha2` is the serialized compatibility profile published by
MALT `v0.0.4`. Its operation set is frozen as:

- `resolve`
- `prove`

The profile never included `resolve_payload`. Adding another operation under
the same discriminator would make a producer incompatible with the v0.0.4
schema and verifiers. Any incompatible extension would require a new profile.

## Status

The Go package `github.com/dewebprotocol/malt-core/artifact`, its schemas under
`artifact/schemas/`, and fixtures under `artifact/testdata/v0alpha2/` remain
available for v0.0.4 compatibility. Core is transport-neutral and no longer
ships the historical `/v1/artifacts/*` HTTP projection. A gateway that
deliberately reintroduces those routes owns their registration, access policy,
and compatibility testing. The artifact profile is not the primary contract
for new integrations.

The `prove` name in this legacy profile means “execute one primitive typed
map/list read and return its evidence.” It is not a general semantic operation
and it does not prove arbitrary resolve or mutation operations.

## Frozen Operations

| Operation | Input | Meaning |
| --- | --- | --- |
| `resolve` | root plus canonical segment path | Return one authenticated path-to-target derivation. An empty path is strict zero-step root identity. |
| `prove` | root plus `map_key`, `list_index`, or `list_range` query | Return one primitive read result and its evidence. |

The historical compatibility HTTP projection was:

```text
POST /v1/artifacts/resolve
POST /v1/artifacts/prove
POST /v1/artifacts/verify
```

Remote verification is diagnostic. A client must bind its independently
selected trusted root and expected request before accepting the result.
These route names are historical documentation, not routes provided by this
module or promised by the current Gateway.

## Embedded Schema Index

Every filename returned by `artifact.SchemaNames()` is indexed here:

<!-- schema-catalog:artifact:start -->
- [`artifact.schema.json`](../../artifact/schemas/artifact.schema.json)
- [`local-verify-request.schema.json`](../../artifact/schemas/local-verify-request.schema.json)
- [`local-verify-result.schema.json`](../../artifact/schemas/local-verify-result.schema.json)
- [`prove-request.schema.json`](../../artifact/schemas/prove-request.schema.json)
- [`resolve-request.schema.json`](../../artifact/schemas/resolve-request.schema.json)
- [`verify-request.schema.json`](../../artifact/schemas/verify-request.schema.json)
- [`verify-result.schema.json`](../../artifact/schemas/verify-result.schema.json)
<!-- schema-catalog:artifact:end -->

## Root Identity Compatibility

The v0.0.4 encoder used `omitempty` for zero path segments and could emit
`{"kind":"path"}`. Conforming v0alpha2 decoders normalize that released form
to `{"kind":"path","segments":[]}`. This narrow normalization preserves the
published profile; it does not authorize adding operations or fields.

## Migration For New Integrations

New clients use the operation-specific contracts in
[Resolve and read contracts](./resolve-read-contracts.md):

- `malt.resolve/v0alpha1` with `ResolveRequest`, `ResolveResult`, and local
  `VerifyResolve`;
- `malt.read/v0alpha1` with `ReadRequest`, `ReadResult`, and local
  `VerifyRead`; and
- ProofList as evidence carried by those results, not as a generic operation.

Payload selection is an ordinary explicit resolve segment. For example,
`["docs", "readme", "@payload"]` authenticates the payload CID, while `[]`
continues to mean strict root identity.

Mutation receipts are not artifacts and are not cryptographic transition
proofs. Until MALT defines and implements a delta/transition-proof contract, a
gateway-returned new root remains a candidate that the client must accept or
publish through an independent policy.

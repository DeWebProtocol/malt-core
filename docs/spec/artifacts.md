# Retired `malt.artifact/v0alpha2` Profile

`malt.artifact/v0alpha2` is the serialized compatibility profile published by
MALT `v0.0.4`. This page records its historical meaning. Its released operation
set was:

- `resolve`
- `prove`

The profile never included `resolve_payload`. Adding another operation under
the same discriminator would make a producer incompatible with the v0.0.4
schema and verifiers. Any incompatible extension would require a new profile.

## Status

Current Core removes the `artifact` package, its embedded schemas and
fixtures, `sdk/verifier.Request`, `sdk/verifier.Result`, `Verifier.Verify`,
and the `maltVerifyArtifact` WASM export. It does not provide an artifact
decoder, verifier, or `/v1/artifacts/*` HTTP projection.

The implementation remains available at the immutable pre-cleanup revision
[`ccae498e29a323eb003b74fb12aa23b87bd13832`](https://github.com/DeWebProtocol/malt-core/tree/ccae498e29a323eb003b74fb12aa23b87bd13832/artifact).
Pin a historical revision to reproduce historical behavior. Current
integrations use the operation-specific contracts below; see also the
[pre-beta API cleanup](../changes/prebeta-cleanup.md).

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

## Historical Schema Index

These schemas belong to the same immutable pre-cleanup revision. They are no
longer embedded or shipped by current Core:

- [`artifact.schema.json`](https://github.com/DeWebProtocol/malt-core/blob/ccae498e29a323eb003b74fb12aa23b87bd13832/artifact/schemas/artifact.schema.json)
- [`local-verify-request.schema.json`](https://github.com/DeWebProtocol/malt-core/blob/ccae498e29a323eb003b74fb12aa23b87bd13832/artifact/schemas/local-verify-request.schema.json)
- [`local-verify-result.schema.json`](https://github.com/DeWebProtocol/malt-core/blob/ccae498e29a323eb003b74fb12aa23b87bd13832/artifact/schemas/local-verify-result.schema.json)
- [`prove-request.schema.json`](https://github.com/DeWebProtocol/malt-core/blob/ccae498e29a323eb003b74fb12aa23b87bd13832/artifact/schemas/prove-request.schema.json)
- [`resolve-request.schema.json`](https://github.com/DeWebProtocol/malt-core/blob/ccae498e29a323eb003b74fb12aa23b87bd13832/artifact/schemas/resolve-request.schema.json)
- [`verify-request.schema.json`](https://github.com/DeWebProtocol/malt-core/blob/ccae498e29a323eb003b74fb12aa23b87bd13832/artifact/schemas/verify-request.schema.json)
- [`verify-result.schema.json`](https://github.com/DeWebProtocol/malt-core/blob/ccae498e29a323eb003b74fb12aa23b87bd13832/artifact/schemas/verify-result.schema.json)

## Root Identity Compatibility

The v0.0.4 encoder used `omitempty` for zero path segments and could emit
`{"kind":"path"}`. Historical v0alpha2 decoders normalized that released form
to `{"kind":"path","segments":[]}`. This describes the retired decoder;
current operation-specific verifiers do not accept an artifact envelope.

## Migration For New Integrations

New clients use the operation-specific contracts in
[Resolve and read contracts](./resolve-read-contracts.md):

- `malt.resolve/v0alpha1` with `ResolveRequest`, `ResolveResult`, and local
  `VerifyResolve`;
- `malt.read/v0alpha1` with `ReadRequest`, `ReadResult`, and local
  `VerifyRead`;
- `malt.map-proof/v0alpha1` with `MapProofRequest`, `MapProofResult`, and local
  `VerifyMapProof`; and
- ProofList as evidence carried by those results, not as a generic operation.

Payload selection is an ordinary explicit resolve segment. For example,
`["docs", "readme", "@payload"]` authenticates the payload CID, while `[]`
continues to mean strict root identity.

Mutation receipts are not artifacts and are not cryptographic transition
proofs. Until MALT defines and implements a delta/transition-proof contract, a
gateway-returned new root remains a candidate that the client must accept or
publish through an independent policy.

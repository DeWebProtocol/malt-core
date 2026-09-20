# Resolve/Read Conformance Corpus V1

> Historical reference: this corpus is retired from the active tree. Its
> original bytes remain in Git history. Current verification uses the
> [V0 corpus v3](./resolve-read-conformance-v3.md).


The v1 corpus is the language-neutral executable contract for local
verification of `malt.resolve/v0alpha1` and `malt.read/v0alpha1` values. The
canonical files live under `conformance/resolve-read/v1/` in this repository:
`vectors.json`, `corpus.schema.json`, and `vector.schema.json`.

## Ownership And Versioning

MALT core owns the corpus, its schema, generation rules, and expected verdicts.
Gateway, native client, browser/WASM, and future language SDK tests consume the
same checked-in bytes; they do not redefine proof semantics or maintain edited
copies.

The corpus version is `malt.resolve-read.conformance/v1`. It is independent
of the enclosed operation profiles and uses structured typed-root
`MALTVersionID=2`. It was introduced on `main` after v0.0.6 and did not
ship with that tag. It is now frozen as the structured-version-2 corpus: a
vector ID, its input, and its expected verdict cannot change. v0.0.7-rc.1
publishes the v2 corpus as the current version. Error strings, timing, and
implementation-specific exception types are not conformance outputs.

## File And Envelope

`conformance/resolve-read/v1/vectors.json` has this shape:

```json
{
  "schema_version": "malt.resolve-read.conformance/v1",
  "vectors": [
    {
      "id": "resolve.identity.accept",
      "operation": "resolve",
      "backend": "none",
      "category": "identity",
      "verification": {
        "request": {},
        "result": {}
      },
      "expected": {"valid": true}
    }
  ]
}
```

Every vector has exactly these fields:

| Field | Contract |
| --- | --- |
| `id` | Stable, unique case identifier. Consumers report it verbatim. |
| `operation` | `resolve` or `read`; selects the operation-specific decoder and verifier. |
| `backend` | `kzg`, `ipa`, or `none`. The current corpus uses `none` for zero-step identity; it is not a commitment backend. |
| `category` | Stable coverage label used by the generator and coverage-matrix test. The schema requires a non-empty string. |
| `verification` | A JSON object conforming to the selected operation's verification contract, or intentionally malformed at the schema/field level for a negative case. |
| `expected.valid` | The only normative outcome: acceptance is `true`, rejection is `false`. |

The corpus itself is valid JSON. Negative cases remain parseable JSON objects.
Malformed-evidence cases remove, truncate, or corrupt encoded proof bytes;
strict-JSON cases add an unknown verification field. Semantic and
cryptographic tampering remain separately categorized. Syntactically invalid
JSON is outside v1.

Consumers must select the verifier from `operation`; they must not infer the
operation from fields inside `verification`, and they must not use `backend` to
override the backend encoded by typed roots. `backend` is test metadata used to
make coverage visible. Typed-root consumers select the backend from the
registered `0x30VSBB` backend ID and validate its declared commitment size;
they must not infer a backend from commitment length.

The current category vocabulary is `identity`, `map_key`, `multihop`,
`payload`, `list_index`, `list_range`, `tamper`, `cross_root`, `cross_kind`,
`cross_backend`, `malformed_evidence`, and `strict_json`. Vectors are sorted by
stable ID so regeneration is byte-deterministic; JSON object key order and
whitespace inside `verification` are not verifier inputs.

## Locked Coverage

The identity case is backend-independent. Every other positive and negative
class below is generated for both KZG and IPA:

| Category | Expected | Checked case |
| --- | --- | --- |
| `identity` | accept | empty resolve segments, equal request/ProofList/result roots, empty query, and no steps |
| `map_key` | accept | grouped-segment resolve and one exact primitive map read of `profile/name` |
| `multihop` | accept | ordered root-map to child-map to leaf resolution |
| `payload` | accept | nested resolve and primitive map read of explicit `@payload -> CID` |
| `list_index` | accept | one stable index with authenticated length and target |
| `list_range` | accept | bounded and authenticated-EOF fixed-width ranges with ordered segment CIDs |
| `tamper` | reject | modified resolve/read primitive proof index, forged read target, or reordered returned range segments |
| `cross_root` | reject | same-backend root splice with evidence retained from another root |
| `cross_kind` | reject | map evidence presented for a list-index request |
| `cross_backend` | reject | KZG evidence under an IPA root, and IPA evidence under a KZG root |
| `malformed_evidence` | reject | invalid base64, missing proof/evidence, or truncated inner proof bytes |
| `strict_json` | reject | unknown field in the operation verification object |

Identity is a strict zero-step contract. It does not execute a commitment
backend or prove an empty path cryptographically. The request root, ProofList
root, and result target must be equal, the ProofList query must be empty, and
the steps array must be empty.

Payload coverage authenticates the relation `@payload -> CID`. It does not
authenticate raw bytes stored under that CID. Full-object and ranged byte
binding remain client/application work after ProofList verification.

Range coverage is limited to the current fixed-width measured-list semantic.
The end is exclusive; an omitted end means the authenticated total size.
Variable-size measured lists are not silently interpreted as v1 evidence.

## Verification Procedure

For each vector, a consumer:

1. validates the corpus envelope and required fields;
2. decodes `verification` using the strict operation-specific JSON contract;
3. constructs the built-in local verifier without network, ArcTable,
   materializer, CAS, gateway, or daemon state;
4. invokes complete request/result verification, not bare ProofList
   verification;
5. maps success to `valid=true` and every decode, shape, binding, semantic, or
   cryptographic rejection to `valid=false`;
6. compares only that boolean with `expected.valid` and reports the vector ID
   on mismatch.

The current protocol decoder also rejects empty input, unknown fields at any
decoded nesting level, trailing JSON values, and inputs larger than 96 MiB.

The complete verification call is essential: cross-root, cross-kind, target,
range-segment, and request/query tampering can remain cryptographically valid
as isolated proof bytes while violating the caller-selected operation.

## JSON Integers And TypeScript

The current profiles encode `index`, `start`, `end`, lengths, and measured
metadata as JSON numbers projected from Go `uint64`. JavaScript's ordinary
`JSON.parse` cannot preserve integers above `2^53-1` exactly.

V1 vectors keep these fields within the safe integer range so ordinary WASM
adapter code does not lose test inputs. A future native TypeScript verifier
must either use a lossless JSON parser and represent protocol integers as
`bigint`, or reject values above `Number.MAX_SAFE_INTEGER` before conversion.
Encoding those fields as strings is not compatible with the current schemas
and would require a new protocol profile.

## Consumer Boundaries

- Go is the reference generator and runs the embedded corpus against the local
  SDK verifier.
- The WASM test feeds the same JSON objects through the exported local-verifier
  boundary. Because the current WASM target contains the Go verifier, this
  proves adapter and serialization parity, not an independent cryptographic
  implementation.
- Gateway tests use the corpus to check their transport adapter without making
  Gateway execution state or publication policy part of core validity.
- Native client tests use the corpus below trust-root, UnixFS, daemon, and
  payload-byte policy. Candidate/accepted root policy is not encoded here.
- A future `malt-ts` implementation must consume the released JSON and obtain
  the same verdicts with its own decoder and verifier before claiming parity.

Product E2E, persistence, scope routing, publication, and accepted-root policy
belong in their owning repositories and must not be added to this corpus.

## Related Documents

- [Resolve and read contracts](./resolve-read-contracts.md)
- [ProofList format](./prooflist-format.md)
- [Commitment and proof encoding](./commitment-proof-encoding.md)
- [CID and wire format](./cid-and-wire-format.md)

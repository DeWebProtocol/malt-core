# Commitment And Proof Encoding

This document describes current V0 primitive and semantic evidence exercised
by Resolve/Read v3, Map-proof v2, and authentication/0 conformance. It complements
[self-describing Roots](./authentication-inputs.md) and
[ProofList format](./prooflist-format.md). Historical V2/V3 Root readers and
semantic proof envelopes are retired; their original source and corpus bytes
remain recoverable in Git history.

Primitive proof encodings and cryptographic parameters are unchanged by this
cleanup. Corpus versions are independent from Root `V=0` and from enclosing
operation profile identifiers. Released corpus bytes are immutable.

## Common Cell And Root Rules

A primitive commitment authenticates an indexed vector of opaque
`commitment.Cell` byte strings. A CID-valued semantic slot is the binary CID
bytes, not its text form. An undefined slot is the empty cell.

Primitive `commitment.Value` objects contain a profile-qualified
multicommitment. Semantic Roots are CIDv1 values with a `0x30VLAA` codec and
an identity multihash over that multicommitment. The codec selects version,
layout, and input rule; the multicommitment selects the exact VC profile:

| Backend | Commitment bytes | Maximum primitive vector length |
| --- | ---: | ---: |
| KZG | 48 | 4096 |
| IPA | 32 | 256 |

The VC profile ID determines the commitment encoding and expected byte length.
Verification must not infer or override the backend from the digest length.

Semantic node geometry is locked to the selected backend suite:

| Backend | Physical node slots | Map radix bits | List content slots |
| --- | ---: | ---: | ---: |
| KZG | 4096 | 12 | 4095 |
| IPA | 256 | 8 | 255 |

Slot zero is an ordinary radix-map slot. List nodes reserve slot zero for
authenticated metadata, leaving the listed number of content slots. KZG
semantic nodes supply all 4096 cells to the primitive commitment; IPA semantic
nodes supply all 256.

## KZG

The current implementation is `auth/commitment/kzg` and uses
`go-kzg-4844` v1.1.0. Its `NewContext4096Secure` supplies the Ethereum KZG
ceremony parameters.

### Cell To Scalar

For each cell:

1. compute SHA-256 over the exact cell bytes;
2. interpret the 32-byte digest as an unsigned big-endian integer;
3. reduce it modulo the BLS12-381 scalar-field modulus
   `0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001`;
4. serialize the result as exactly 32 big-endian bytes.

The fixed 4096-position blob is zero-filled after the supplied cells.

### Index Domain

Index openings use a 4096-point BLS12-381 scalar-field domain. The
implementation starts from the order-`2^32` root
`10238227357739495823651030575849232062558860180284477541189508159991286009131`,
raises it to `2^(32-log2(4096))`, enumerates successive powers beginning with
one, and bit-reverses the resulting array. Position `i` is opened at domain
point `domain[i]`.

### Single Proof

A KZG index proof is exactly 84 bytes:

| Offset | Size | Encoding |
| ---: | ---: | --- |
| 0 | 48 | compressed KZG proof |
| 48 | 32 | claimed scalar, in the backend scalar serialization |
| 80 | 4 | index as unsigned big-endian `uint32` |

Verification rejects any other length, an index above 4095, a proof-carried
index different from the requested index, or a claimed scalar different from
the SHA-256-derived cell scalar.

### Current Batch Proof

KZG batch proof generation currently concatenates single proofs; it is not a
native KZG multi-opening. Its bytes are a 4-byte unsigned big-endian proof
count followed by that many 84-byte single proofs in caller-supplied index
order. The ordered index and cell arrays are supplied separately to
verification.

## IPA

The current implementation is `auth/commitment/ipa`. Its pinned upstream
source snapshot is compiled inside the MALT module at
`internal/third_party/goipa`; it is not resolved as an external module during
consumer builds. The snapshot is
`github.com/crate-crypto/go-ipa@53bbb0ceb27adb011950fd0fce885ad6d4516f84`
(formerly represented by pseudo-version
`v0.0.0-20240724233137-53bbb0ceb27a`). Import paths are mechanically rewritten
to the internal location. The behavioral patch is restricted to:

- `ipa/config.go`, which exposes verifier-only settings and the direct,
  compact, and fast committer profiles;
- `banderwagon/precomp.go`, which permits the compact uniform 4-bit
  fixed-base table; and
- `multiproof.go`, which propagates commitment errors instead of relying on a
  panic-returning call.

The `direct`, `compact`, and `fast` profiles are execution strategies over the
same 256-point SRS and auxiliary point `Q`. They differ only in retained
fixed-base MSM tables. Profile-equivalence tests require byte-identical typed
roots, commitments, single proofs, and batch proofs. A profile identifier is
therefore runtime provenance and is not part of any commitment or proof wire
encoding.

The parameter set identifier is `malt.ipa-parameters/v1`. Its fingerprint is
SHA-256 over the identifier, one zero byte, the 256 ordered compressed SRS
points, and compressed `Q`; the current digest is
`3799df0a77d1843b13a3a08744165180a12e1cd2dca529bee64ad691ac63adaf`.
`auth/commitment/ipa.ParameterSetID` and `ParameterSHA256()` are the source of
these release-provenance values, and `go run ./cmd/malt-ipa-parameters` exports
them as JSON. The digest binds only the SRS and `Q`, not transcripts, cell
hashing, CID typing, or proof encodings. Any change to those surrounding suite
rules still requires an explicit compatibility review even if the parameter
digest is unchanged; changing the parameters requires a new backend/wire
identity rather than selecting another performance profile.

The 256 SRS points are generated deterministically. Starting with counter zero,
hash ASCII `eth_verkle_oct_2021` followed by the counter as big-endian `uint64`,
interpret the digest as an unsigned big-endian integer reduced modulo the
BLS12-381 scalar modulus used as the Bandersnatch base field, serialize it as
32 big-endian bytes, pass that encoding to Banderwagon point decoding, skip
unsuccessful decodes, and continue until 256 points have been accepted. The IPA
auxiliary point `Q` is the dependency's `banderwagon.Generator`.

### Cell To Scalar

For each cell, compute SHA-256 over the exact bytes, interpret the digest as an
unsigned big-endian integer, and reduce it modulo the Bandersnatch scalar-field
modulus
`13108968793781547619861935127046491459309155893440570251786403306729687672801`.
The fixed 256-element vector is zero-filled after the supplied cells. The
commitment is the multiscalar multiplication of that vector by the ordered SRS;
commitment bytes are the 32-byte `banderwagon.Element.Bytes()` result.

### Single Proof

Single openings use transcript label `malt-ipa` and the field element created
from the requested integer index as the evaluation point. The proof encoding
is:

| Order | Size | Encoding |
| --- | ---: | --- |
| round count | 4 | unsigned big-endian `uint32` |
| `L[0..rounds)` | `32 * rounds` | each `banderwagon.Element.Bytes()` |
| `R[0..rounds)` | `32 * rounds` | each `banderwagon.Element.Bytes()` |
| `A_scalar` | 32 | little-endian field element |
| index | 4 | unsigned big-endian `uint32` |

For the current 256-element vector, there are eight rounds and the proof is
552 bytes. Verification requires the proof-carried index to equal the requested
index.

### Current Batch Proof

Batch openings use transcript label `malt-ipa-batch`. The locked internal
snapshot's `MultiProof.Write` encoding is 576 bytes: the 32-byte `D` point,
eight 32-byte `L` points, eight 32-byte `R` points, and a 32-byte little-endian
`A_scalar`. It contains no count or index list; the ordered indices and
expected cells are separate verifier inputs.

## Current semantic binding proof

Both Prefix and Positional evidence serialize `engine.Proof` as JSON:

```json
{
  "format": "malt.binding/0",
  "nodes": [
    {
      "cell": "<base64 cell bytes>",
      "proof": "<base64 primitive opening>",
      "metadata": "<base64 Positional metadata>",
      "metadata_proof": "<base64 Positional metadata opening>"
    }
  ]
}
```

Empty byte fields are omitted. Prefix proofs carry only the selected cell and
opening at each node. A terminal empty cell or a routed leaf for another key
proves absence. Positional proofs also open slot-zero metadata at every node;
a root-level out-of-range result contains only metadata evidence. All supplied
nodes must be consumed. Metadata, leaf, and internal child framing follow
[authentication inputs and Roots](./authentication-inputs.md).

Resolve stores Prefix evidence in `step.evidence` with
`evidence_kind="explicit"`. Map and List reads use `step.proof` with
`evidence_kind="structure"` and the appropriate semantic evidence backend.
The verifier derives coordinates from the caller's Root and query; it never
uses a proof-supplied key or a historical semantic CID for primitive openings.

## Fixed-width Positional range proof

The range envelope is the JSON projection of `engine.RangeResult`, containing
`metadata`, `metadata_evidence`, and ordered `segments`. Each evidence value is
an `engine.Result` with `present`, `target`, and its `malt.binding/0` proof.
The metadata evidence opens the always-out-of-range maximum uint64 index.
Segment results open precisely the indices selected by the requested byte
range. The verifier checks the metadata opening, bounds, order, and targets.
The Map/List convenience API carries this envelope in `step.proof` with
`evidence_backend="measured_list"`.

Only fixed-width measured lists are supported. Byte verification under each
returned payload CID remains application work.

## JSON Projection

ProofList CID fields serialize as IPLD-link objects such as
`{"/":"<cid>"}`. Go `[]byte` fields serialize as standard padded base64
strings. Implementations must treat decoded proof bytes, CID bytes, segment
order, integer widths, and optional-field presence as verifier inputs; error
message text is not part of conformance.

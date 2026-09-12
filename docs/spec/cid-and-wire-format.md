# CID and Wire Format

MALT uses typed CIDv1 roots for authenticated map and list structure. Payload
objects remain ordinary CAS CIDs.

## Status

Experimental and implementation-bound. Constructors emit the current layout;
the immediately preceding v2 layout remains accepted for read/proof compatibility.

This reference describes the checked-in `0x30VSBB` implementation, inspected
at `c90b4d35ec95003b14422546b777fbf9ada2b0c7`. The maintainer's newer
[Root version policy](../policy/root-versioning.md) requires the planned
self-describing Root refactor to use `V=0` until an explicit production-ready
go-live declaration authorizes `V=1`. It does not change current code or
historical Root bytes. [MIP-1014](../mips/mip-1014-self-describing-roots.md)
records the proposed `0x30VLAA`/multicommitment boundary and migration scope.

## MALT Root Codec Namespace

Multicodec reserves `0x300000-0x3FFFFF` as a Private Use Area. MALT typed
roots use only the `0x300000-0x30FFFF` subrange. Values in
`0x310000-0x3FFFFF` are not MALT typed-root codecs.

The CIDv1 content-type multicodec remains an unsigned varint. The
`0x30VSBB` notation below describes fields in the decoded codec integer; it
does not append two literal bytes to the CID.

## `0x30VSBB` Layout

The low 16 bits of a MALT root codec have three fields:

| Field | Bits | Meaning |
| --- | ---: | --- |
| `V` | 4 | MALT typed-root wire-format version |
| `S` | 4 | semantic kind |
| `BB` | 8 | commitment backend suite |

The normative construction is:

```text
codec = 0x300000
      | (malt_version_id << 12)
      | (semantic_id << 8)
      | backend_id
```

The current `MALTVersionID` is `3`. It identifies this typed-root layout;
it is not the CID version, a source release, a Resolve/Read profile, or a
conformance-corpus version. Adding a semantic kind or backend suite does not
change it. Earlier experimental revisions incremented it when codec or
commitment-envelope interpretation changed incompatibly. Future allocation
follows the Root version policy above and keeps pre-production `V=0` even
across experimental refactors; compatible parsing still requires explicit
profile and framing rules.

### Semantic Registry

| ID | Kind |
| ---: | --- |
| `0x0` | invalid |
| `0x1` | map |
| `0x2` | list |
| `0x3-0xF` | unassigned |

### Commitment Backend Registry

Backend IDs identify complete commitment suites, including parameters,
commitment encoding, and commitment-size validation. They are not inferred
from digest length.

| ID | Backend suite | Commitment size |
| ---: | --- | ---: |
| `0x00` | invalid | - |
| `0x01` | current KZG suite | 48 bytes |
| `0x02` | current IPA suite | 32 bytes |
| `0x03-0xFF` | unassigned | - |

An incompatible parameter set or commitment encoding receives a new backend
ID even when it belongs to the same broad cryptographic family.

### Current Codecs

| Name | Value | Semantic kind | Backend |
| --- | ---: | --- | --- |
| `malt-map-kzg` | `0x303101` | map | KZG |
| `malt-list-kzg` | `0x303201` | list | KZG |
| `malt-map-ipa` | `0x303102` | map | IPA |
| `malt-list-ipa` | `0x303202` | list | IPA |

The implementation owner is `wire/maltcid`.

## Commitment Encoding

Typed MALT root CIDs use CIDv1 with an identity multihash carrying the raw
commitment bytes.

Current commitment byte sizes:

| Backend | Size |
| --- | ---: |
| KZG | 48 bytes |
| IPA | 32 bytes |

Code that creates or validates typed roots must select the backend descriptor
from `BB` and reject commitment byte lengths that do not match it. Length
alone must never select or override the backend.

## Root Classification

`wire/maltcid` exposes helpers for:

- detecting whether a CID is a MALT structure root
- extracting the encoded MALT wire-format version
- extracting semantic kind: `map`, `list`, or `unknown`
- extracting backend kind: `kzg`, `ipa`, or `unknown`
- extracting raw commitment bytes from a typed MALT root CID
- comparing commitment bytes across typed roots

A supported typed root must satisfy all of these checks:

1. its codec is in `0x300000-0x30FFFF`;
2. `V` equals the current `MALTVersionID` or the explicitly registered legacy v2 ID;
3. `S` and `BB` are nonzero registered IDs and their combination is
   supported;
4. the multihash code is identity;
5. the identity digest length matches the selected backend descriptor.

Unknown versions other than registered v2 compatibility, unknown semantics,
backends, combinations, and codecs outside the typed-root subrange fail closed. Classifiers must validate the complete codec
before returning either semantic or backend; independently masking one field
is insufficient.

Version 3 introduces fixed-domain collision buckets for sound map
non-membership proofs. New constructors emit v3 roots. Version-2 roots remain
classified and verifiable; their legacy variable-length collision buckets
remain membership-readable but cannot provide collision-bucket non-membership
proofs. Incremental mutation requires the root version to match the semantic
instance. A v2 update therefore requires exact complete-view replay followed by
a full v3 rebuild before any change; partial path-only v2-to-v3 rewrites are
rejected because they would retain unchanged v2 child CIDs under a v3 root.

Version 2 makes semantic node geometry backend-sized: KZG map and list nodes
use all 4096 positions in the current KZG suite, while IPA nodes retain the
current suite's 256 positions. Map radix digits and list branching therefore
also depend on the backend suite. Version-1 experimental roots are not
recognized by current decoders and must be rebuilt together with their
materialized node state.

Verifiers must also reject roots or proof steps whose semantic kind, backend
kind, or expected target type does not match the query and evidence.

Proof producers follow the same rule. For an operation over an existing root,
`S` selects the semantic implementation and `BB` selects the commitment
prover. Runtime configuration may restrict the registered backends, but it
must not override the backend encoded by the root. Multi-step resolution makes
this selection independently for every proof step from that step's `from`
root, so linked structures may use different registered backends.

An operation that creates a structure without an existing root has no codec
from which to select a backend. Its executor therefore uses an explicit or
configured default backend; all later operations use the backend encoded in
the resulting root CID.

## Payload CIDs

Immutable file bytes, chunks, manifests, and other payload objects keep their
ordinary CAS CIDs. MALT authenticates bindings to those payload CIDs; it does
not redefine the payload CID format.

## Related Documents

- [Commitment model](./commitment.md)
- [ProofList format](./prooflist-format.md)
- [Compatibility policy](../policy/compatibility.md)

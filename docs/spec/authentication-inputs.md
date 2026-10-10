# Authentication inputs and self-describing Roots

Status: experimental implementation, Root `V=0`. This is the current construction
contract. The [Root version policy](../policy/root-versioning.md) requires an
explicit maintainer production-ready declaration before `V=1` is permitted.
It is independent of CIDv1, package versions and operation-profile suffixes.

## Pipeline and API ownership

```text
application label --coordinate derivation--> authentication coordinate
original labels + targets + routing coordinates --layout + exact VC profile--> commitment
Root descriptor + commitment --> CIDv1 Root
```

`derivation.Derive` owns deterministic coordinate derivation. `engine`
exposes `Interpret`, `Commit`, `Build`, binding proofs, explicit traversal,
ranges and incremental updates. `sdk/authentication` composes these operations
with candidate preparation, materialization and independent verification.
The engine consumes narrow `materializer.NodeLookup`/`NodeUpdater` capabilities;
it contains no persistent ArcTable, CAS, HTTP, application path or trust policy.

Prefix accepts SHA256 (AA=4) or Direct (AA=3) 32-byte coordinates;
Positional uses Direct (AA=3) uint64 coordinates. AA is the Root byte carrying
the coordinate derivation profile ID. A slash has no special meaning in a
label; applications supply explicit label traversal steps.

## Root and multicommitment

The codec integer is `0x300000 | (V << 12) | (L << 8) | AA`, abbreviated
`0x30VLAA`. This integer is serialized as a minimal unsigned varint by CIDv1;
the notation does not mean four literal prefix bytes.

```text
multicommitment = uvarint(profile_id) || uvarint(commitment_length) || commitment
Root = CIDv1(codec, identity_multihash(multicommitment))
```

The length must equal the exact registered profile's length. Unknown profiles,
nonminimal varints, trailing bytes, other hash containers, unsupported versions
are rejected by the wire parser. `maltcid.ParseRoot`
decodes the descriptor; an engine additionally requires a supported derivation/layout combination
and an installed commitment profile. Parsing an unknown AA is not
permission to execute it. No fallback derivation or backend inference is used.

| L | Authentication layout | Permitted inputs |
| --- | --- | --- |
| 4 | Prefix | Original labels routed by AA-derived 32-byte keys |
| 3 | Positional | AA=3, unsigned 64-bit indices |

| Profile | Algorithm and parameters | Commitment bytes | VC slots |
| --- | --- | ---: | ---: |
| 1 | KZG/BLS12-381, embedded 4096-point setup | 48 | 4096 |
| 2 | IPA/Banderwagon over Bandersnatch, fixed 256-point SRS | 32 | 256 |

`maltcid.Profile` records the parameter fingerprints and encoding names.
Profile 1's embedded setup SHA-256 is
`0229b43f4fac9b17374809520eb621b5ee1a7f74547e7d36918e7d4b122e178d`.
Profile 2's domain-separated compressed SRS fingerprint is
`3799df0a77d1843b13a3a08744165180a12e1cd2dca529bee64ad691ac63adaf`.
The exact parameter generation, cell-to-scalar conversion, commitment and
opening encodings are fixed by `auth/commitment/kzg` and `auth/commitment/ipa`
and the current conformance corpus. A changed parameter set or cryptographic
encoding requires a new immutable profile ID even within the same algorithm.
IPA direct/compact/fast precomputation choices do not change profile identity.

Use `RootVersion`, `NewRoot`, and `ParseRoot` for current construction.
Historical version constants and constructors are removed. A codec alone
cannot identify a V0 Root's VC profile.

## Coordinate derivation profiles

Application labels are opaque byte strings. Go APIs use `[]byte`; JSON uses a
canonical padded standard-base64 string. There is no tagged input union. Empty
labels are valid for SHA256; JSON null and missing labels are rejected. In Go,
use an allocated empty slice for an empty label, not nil.

`auth/coordinate.Coordinate` is a Key (`[32]byte`) or Index (`uint64`), with only
the selected field active. `derivation.Derive(profile, label)` returns this type.
It is a shared pure function outside `auth`; no mutable rule registry exists.

| AA | Profile | Behavior |
| --- | --- | --- |
| 3 | Direct | Parse exactly 32 key bytes or 8 unsigned big-endian index bytes |
| 4 | SHA256 | Derive a 32-byte key from arbitrary label bytes |

Direct preserves canonical encoding: `Encode(Derive(Direct, label)) == label`.
Use `coordinate.EncodeIndex` and `coordinate.EncodeKey` to submit precomputed
coordinates as labels. Text numbers, padded keys, and truncated indices are not
coerced. The selected layout must accept the resulting coordinate kind.
SHA256 uses this exact framing:

```text
D = UTF8("malt:coordinate:sha256:0") || 0x00
coordinate = SHA256(D || uvarint(byte_length) || label_bytes)
```

The varint is minimal. No UTF-8 validation, path splitting, Unicode
normalization, case folding, system selector, or payload redirection occurs.
`@payload` is an ordinary label; application binding conventions define reserved
names and namespace isolation. Under Direct, any application payload label must
itself be a canonical coordinate encoding. Private preprocessing is performed
before submission and may require application-specific payload discovery.

IDs 0–2 retain their retired typed-input meanings in Git history and are not
accepted by the current engine. New profiles require immutable specifications,
implementation and conformance vectors; unsupported IDs fail closed. The Root
codec parses profile IDs structurally without importing derivation. `engine`
checks supported profiles and layout compatibility even for empty state and
empty traversal. `auth/tree` authenticates original label bytes and targets,
uses coordinates for routing, and consumes a pure injected derivation capability.
It does not import the derivation package or interpret application labels.

## Authentication layout and internal node identity

Prefix and Positional organize coordinate bindings within one authentication
tree. Flat and compositional ArcSet organization describe how an application
groups bindings across Roots. That application choice is not a Root field;
the same ArcSet may be used in either organization or a mixture of them.

Prefix routes over all 256 key bits (12 bits per KZG level, 8 per IPA level;
the final KZG digit is zero-padded). Layout 4 terminal cells contain
`0x01 || uvarint(label byte length) || original label bytes || targetCID`.
The length is minimal, the label is opaque (including empty bytes), and the
target is the complete canonical binary CID. The routing key is recomputed
from the authenticated label under the selected Root's AA; it is not duplicated
in the cell. Membership compares exact original label bytes and the target.
An empty slot or a routed terminal label with a different full coordinate proves
absence. Distinct labels at the same full coordinate return
`ErrCoordinateCollision`, including during proof generation, membership/absence
verification, construction, updates and recovery. Duplicate labels are rejected.
Native keys are not rehash inputs. Layout 1 is retired and rejected; Root `V`
remains zero. Cell encodings are defined in `maltcid/node_cells.go` and
`auth/tree`; changing them must not silently reuse a descriptor's interpretation.

Positional consumes dense indices `[0,count)` using canonical index labels.
Only root slot 0 stores metadata: count and an optional opaque payload CID.
The root has `slots-1` entry/child slots; descendants use all `slots` positions.
Count authenticates sequence bounds and determines tree height and occupancy.
Core range queries select element indices. Applications may bind byte geometry
through the root payload CID, verify its content, and translate byte ranges
into those indices as described below.

Internal references are `"MN" || 0x00 || byte(L) || multicommitment`.
They identify authentication nodes, not application vertices, and omit AA.
The root descriptor supplies coordinate derivation; an internal node is
interpreted with its layout and exact VC profile. Application-valued targets
retain complete Roots/CIDs, including the target Root's AA. Each explicit
traversal step uses the AA of the Root reached by the preceding verified step.

Equal coordinates and targets do not establish interchangeable Prefix leaves:
their original labels must also match. In particular, an opaque SHA256 label
and its Direct key encoding authenticate different leaf bytes. Reuse across
AA modes requires identical authenticated vectors and valid routing under each
selected Root; complete Roots remain distinct.
Caches validate the node identity, full vector and exact profile before reuse.
`EqualCommitment` does not establish interchangeable Root/query semantics.

## Positional root metadata and geometry

Layout 3 reserves **only root slot 0** for `0x04 || uint64be(count) || payloadCID`.
The CID is optional: absence ends after the nine-byte tag/count prefix; presence
uses the complete canonical binary CID through the end of the cell. A defined
CID of empty content differs from absence. Core does not fetch or decode it.
Layout 2 is retired and rejected. Root `V` remains zero.

With physical capacity `C=2^k` (`k=8` for IPA, `12` for KZG), the root has `C-1`
content slots and every descendant has `C`. Height `H` is the smallest
nonnegative integer satisfying `count <= (C-1)*C^H`, with `H=0` for empty state.
Cells are densely packed left to right; all unused positions are empty. Internal
cells reference children, leaf cells contain `0x03 || targetCID`. Child references
retain the existing `0x02 || NodeRef` framing. No descendant stores metadata.

For index `i`, the root selects `1 + (i >> (k*H))`. Each subsequent level selects
the next `k`-bit digit `(i >> (k*h)) & (C-1)`; the leaf uses `i & (C-1)`.
A height-zero root selects `i+1`. Child counts and padding follow from count and
traversal context. Implementations must handle virtual spans at or above `2^64`
without overflow. Membership proofs open metadata once at the root; any
metadata attached to a descendant proof is rejected.

At capacity 256, count 255 fits a root leaf, count 256 uses one full descendant
leaf, and count 257 uses two leaves. When a root becomes a descendant, move its
content slots 1..C-1 to 0..C-2 and recompute that vector; descendant references
can be reused. Root promotion does the inverse. Append and truncation preserve
the root payload CID, even when truncating to zero. `SetPayload` updates only
the root. `Height`, byte sizes and per-node counts are never serialized.

`ProveRange`/`VerifyRange` authenticate the half-open **element index** interval
`[start,end)`, with omitted end equal to count. Bounds require
`0 <= start <= end <= count`. Applications such as UnixFS may bind JSON byte
geometry through the root payload CID, verify those bytes, and translate their
byte interval into element indices. Heterogeneous lists need no byte geometry.

## State, writes and proofs

The authenticated view contains original labels, targets and their checked
routing coordinates. `engine.State` retains application labels for construction;
applications or Gateway-owned ArcTable records may independently retain the
same label–target bindings for enumeration and writes. Prefix recovery reads
labels from authenticated cells; Positional recovery reconstructs canonical
index labels. Deltas, tombstones, checkpoints and lineage recovery operate on
labels. `ValidateState` and `MatchView` compare exact labels, coordinates and
targets against root-bound materialization. A query never accepts a distinct
label merely because its coordinate matches. Coordinate collisions are explicit
errors and do not create collision buckets or overwrite existing bindings.

`PrefixApply` and Positional replacement/append/truncation reuse unchanged
subtrees. Updates check expected bindings before exposing a result Root. I/O
failure may leave unreachable immutable nodes in the caller-owned store.
Candidate preparation and materialization do not publish or trust a Root and
do not prove a transition from a previous Root. A candidate's optional
`previous` field is storage lineage only.

The current query (`malt.authentication/5`) and candidate (`malt.authentication/4`)
JSON contracts live in `protocol/authentication.go`
and `protocol/schemas/authentication*.schema.json`. Queries select a Root,
explicit label traversal steps, and resolve/binding/range operation. Range
endpoints and structural uint64 metadata use decimal strings. Results contain
root-bound traversal and primitive evidence. A verifier uses the caller's
request, never a server-rewritten root or key, and performs no network lookup.
Unknown AA/profile combinations fail even for an empty traversal.

Candidates include original labels and the complete reachable node vectors.
Validation rejects conflicting, missing and unreachable records before
materialization, and bounds logical expansion by the supplied binding count.
Service code should use `SnapshotBounded` when reconstructing untrusted state;
unbounded `Snapshot` is intended for callers that already bound their state.

## Compatibility and evidence

Current builders and readers use V0. V2/V3 Roots are rejected, and the client
writer does not migrate historical update views. Recreate old experimental
state and dependent parents with the current implementation. Replacing a Root
prefix alone is not a migration; payload CIDs remain reusable.

`conformance/authentication-v3.json` is generated from current queries over
V=0 Roots. Historical authentication/0 vectors remain only in Git history and are not
accepted by the current verifier. See [conformance corpora](./conformance-corpora.md). Measurements
must identify their exact Core revision, profile, and corpus. Browser release
assets remain subject to `malt-ts`'s exact published-Core lock and conformance
gate.

## SDK backend selection

`sdk/authentication` consumes a caller-supplied `engine.Engine` for
preparation, execution, materialization, and verification. It imports no
concrete commitment backend. Applications that want the built-in verification
profiles may opt into `sdk/authentication/builtin.NewVerifier`; that separate package
imports KZG and IPA. Backend-specific writer builds keep their selected backend
injected and must not import this convenience constructor.

## Rooted paths and retained writers

`malt.authentication/5` supports authenticated early path termination. A missing
traversal selector returns `absent_step` as a zero-based decimal string, an
empty `resolved`, and exactly the successful prefix proofs followed by the
missing binding proof. It carries neither a primitive binding nor a range
result. Verification binds that prefix to the caller's Root and steps; it does
not claim to have evaluated the suffix. I/O, recovery, unsupported-input and
cancellation errors never become absence. Historical query and candidate profiles are rejected. Complete candidates use
the independent `/4` candidate profile.

`ExecuteWithRoots` accepts a Root-scoped node lookup. A service can reconstruct
one ArcSet before serving its proof and defer other Roots until traversal
reaches them. Core defines no recovery records, durable store or cache policy.

`authentication.NewWriter` imports and verifies a complete candidate once.
`Writer.Update` returns an independent candidate writer, preserving its base for
retries and branches. Prefix changes and Positional replacement, append,
truncation and opaque payload changes reuse unchanged authentication paths.
The exported candidate remains a complete input/node view: this is neither a
partial update witness nor a stateless transition proof. Complete export still traverses the materialization, but does not repeat
cryptographic validation of owned nodes; path reuse does not imply constant
update or transport cost. Applications update child ArcSets before rebinding
parent entries, and retain candidate writers only under their own receipt and
trust policies.

Truncation supplies an explicit new count. `SetPayload` changes the optional
root payload CID; it never decodes application content. Applications update
changed final chunks and their metadata together before publishing a candidate.

## Independent tree and explicit export

`auth/tree` implements single-ArcSet authentication over original labels and
their `auth/coordinate` routing values. `tree.New` requires an exact VC registry
and a pure derivation capability; low-level selectors and bindings carry both
original label bytes and checked coordinates. The typed `engine` supplies
Root-selected coordinate derivation; `traversal`
composes proofs across Roots. These are separate from application flat/rooted
organization and from Gateway relation persistence.

For a retained writer, `Apply(ctx, Delta)` accepts expected-before label changes.
Prefix supports insert/replace/delete. Positional changes replace existing
positions or supply appended bindings; `Count` controls suffix length and
`PayloadCID` optionally replaces or clears the application metadata reference. `Update(ctx, State)` compiles complete desired inputs to
the same path, with an unavoidable input scan.

Use `Root()` for the candidate identity and `Export(ctx)` when a complete
portable candidate is needed. `Candidate()` also performs a complete export.
Export is no longer part of every update. A new or externally imported writer
owns its immutable vectors; unchanged subtrees can be shared across independent
branches without revalidating them or retaining obsolete ancestors. External
materializations still undergo complete Root-bound validation.

The corresponding JSON delta profile is `malt.authentication-delta/2`; the
[schema](../../protocol/schemas/authentication-delta.schema.json) requires typed
changes, optional decimal-string count and payload CID, and exact field names. It is
an instruction for retained complete state, not an authenticated-update witness.
See [implementation and lifecycle details](../changes/authentication-tree.md).

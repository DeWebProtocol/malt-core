# Authentication inputs and self-describing Roots

Status: experimental implementation, Root `V=0`. This is the current construction
contract. The [Root version policy](../policy/root-versioning.md) requires an
explicit maintainer production-ready declaration before `V=1` is permitted.
It is independent of CIDv1, package versions and operation-profile suffixes.

## Pipeline and API ownership

```text
application label --coordinate derivation--> authentication coordinate
coordinate bindings --authentication layout + exact VC profile--> commitment
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
are rejected by the wire parser. `wire/maltcid.ParseRoot`
decodes the descriptor; an engine additionally requires a supported derivation/layout combination
and an installed commitment profile. Parsing an unknown AA is not
permission to execute it. No fallback derivation or backend inference is used.

| L | Authentication layout | Permitted inputs |
| --- | --- | --- |
| 1 | Prefix | AA-derived 32-byte keys |
| 2 | Positional | AA=3, unsigned 64-bit indices |

| Profile | Algorithm and parameters | Commitment bytes | VC slots |
| --- | --- | ---: | ---: |
| 1 | KZG/BLS12-381, embedded 4096-point setup | 48 | 4096 |
| 2 | IPA/Banderwagon over Bandersnatch, fixed 256-point SRS | 32 | 256 |

`wire/maltcid.Profile` records the parameter fingerprints and encoding names.
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
empty traversal. `auth/tree` handles only coordinates, layout and commitments.

## Authentication layout and internal node identity

Prefix and Positional organize coordinate bindings within one authentication
tree. Flat and compositional ArcSet organization describe how an application
groups bindings across Roots. That application choice is not a Root field;
the same ArcSet may be used in either organization or a mixture of them.

Prefix routes over all 256 key bits (12 bits per KZG level, 8 per IPA level;
the final KZG digit is zero-padded). Terminal cells bind the full key and target
CID. An empty slot or a different full key proves absence. Native keys are not
rehash inputs. Collisions and duplicate coordinates are rejected. Cell encodings
are defined in `wire/maltcid/node_cells.go` and `auth/tree`; changing them must
not silently reuse an existing descriptor's interpretation.

Positional consumes dense indices `[0,count)`. Slot 0 contains structural
height/count/chunk-size/total-size metadata; the remaining `slots-1` cells are
entries or child references. Metadata is authenticated, including absence
beyond count and fixed-chunk range boundaries. Positional labels use canonical index bytes. To associate payload/metadata content with a sequence, a containing
Prefix binds the sequence Root and the content CID as separate targets.

Internal references are `"MN" || 0x00 || byte(L) || multicommitment`.
They identify authentication nodes, not application vertices, and omit AA.
The root descriptor supplies coordinate derivation; an internal node is
interpreted with its layout and exact VC profile. Application-valued targets
retain complete Roots/CIDs, including the target Root's AA. Each explicit
traversal step uses the AA of the Root reached by the preceding verified step.

Equal normalized coordinates and targets can therefore reuse commitments and
internal nodes across AA modes, while the complete Roots remain distinct.
Caches validate the node identity, full vector and exact profile before reuse.
`EqualCommitment` does not establish interchangeable Root/query semantics.

## State, writes and proofs

The authenticated view contains coordinates, not original label preimages.
`engine.State` retains application labels for interpretation; applications or
Gateway-owned ArcTable records preserve label–target bindings for enumeration
and future writes. Deltas, tombstones, checkpoints and lineage recovery operate
on labels. Coordinates and authentication nodes are rebuildable indexes:
recover labels, derive coordinates, materialize the tree, and check the exact Root.
`ValidateState` derives coordinates again and checks them against root-bound
materialization. Proofs authenticate derived coordinates and targets; retaining labels does not
turn a hash into a proof of a unique preimage. Duplicate derived keys in one state fail.

`PrefixApply` and Positional replacement/append/truncation reuse unchanged
subtrees. Updates check expected bindings before exposing a result Root. I/O
failure may leave unreachable immutable nodes in the caller-owned store.
Candidate preparation and materialization do not publish or trust a Root and
do not prove a transition from a previous Root. A candidate's optional
`previous` field is storage lineage only.

The current query (`malt.authentication/3`) and candidate (`malt.authentication/2`)
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

`conformance/authentication-v2.json` is generated from current queries over
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

`malt.authentication/3` supports authenticated early path termination. A missing
traversal selector returns `absent_step` as a zero-based decimal string, an
empty `resolved`, and exactly the successful prefix proofs followed by the
missing binding proof. It carries neither a primitive binding nor a range
result. Verification binds that prefix to the caller's Root and steps; it does
not claim to have evaluated the suffix. I/O, recovery, unsupported-input and
cancellation errors never become absence. Historical query and candidate profiles are rejected. Complete candidates use
the independent `/2` candidate profile.

`ExecuteWithRoots` accepts a Root-scoped node lookup. A service can reconstruct
one ArcSet before serving its proof and defer other Roots until traversal
reaches them. Core defines no recovery records, durable store or cache policy.

`authentication.NewWriter` imports and verifies a complete candidate once.
`Writer.Update` returns an independent candidate writer, preserving its base for
retries and branches. Prefix changes and Positional replacement, append,
truncation and measured-size changes reuse unchanged authentication paths.
Changing chunk geometry explicitly falls back to complete materialization.
The exported candidate remains a complete input/node view: this is neither a
partial update witness nor a stateless transition proof. Complete export still traverses the materialization, but does not repeat
cryptographic validation of owned nodes; path reuse does not imply constant
update or transport cost. Applications update child ArcSets before rebinding
parent entries, and retain candidate writers only under their own receipt and
trust policies.

Measured truncation uses `ResizeMeasured` with an explicit new count and total
size. The application supplies any changed final payload CID separately; Core
cannot infer re-chunked content or verify its bytes from relation state.

## Independent tree and explicit export

`auth/tree` implements single-ArcSet authentication over `auth/coordinate`
values. The typed `engine` supplies coordinate derivation; `traversal`
composes proofs across Roots. These are separate from application flat/rooted
organization and from Gateway relation persistence.

For a retained writer, `Apply(ctx, Delta)` accepts expected-before label changes.
Prefix supports insert/replace/delete. Positional changes replace existing
positions or supply appended bindings; `Count` controls suffix length, and
measured length changes require `TotalSize`. Changing chunk geometry uses full
`Update`/construction. `Update(ctx, State)` compiles complete desired inputs to
the same path, with an unavoidable input scan.

Use `Root()` for the candidate identity and `Export(ctx)` when a complete
portable candidate is needed. `Candidate()` also performs a complete export.
Export is no longer part of every update. A new or externally imported writer
owns its immutable vectors; unchanged subtrees can be shared across independent
branches without revalidating them or retaining obsolete ancestors. External
materializations still undergo complete Root-bound validation.

The corresponding JSON delta profile is `malt.authentication-delta/1`; the
[schema](../../protocol/schemas/authentication-delta.schema.json) requires typed
changes, optional decimal-string count/total size, and exact field names. It is
an instruction for retained complete state, not an authenticated-update witness.
See [implementation and lifecycle details](../changes/authentication-tree.md).

# Authentication inputs and self-describing Roots

Status: experimental implementation, Root `V=0`. This is the current construction
contract. The [Root version policy](../policy/root-versioning.md) requires an
explicit maintainer production-ready declaration before `V=1` is permitted.
It is independent of CIDv1, package versions and operation-profile suffixes.

## Pipeline and API ownership

```text
typed input --AA rule--> authentication coordinate
coordinate bindings --layout + exact VC profile--> commitment
Root descriptor + commitment --> CIDv1 Root
```

`auth/input.Registry` owns deterministic input interpretation. `auth/engine`
exposes `Interpret`, `Commit`, `Build`, binding proofs, explicit traversal,
ranges and incremental updates. `sdk/authentication` composes these operations
with candidate preparation, materialization and independent verification.
The engine consumes narrow `materializer.NodeLookup`/`NodeUpdater` capabilities;
it contains no persistent ArcTable, CAS, HTTP, application path or trust policy.

Map/List remain convenience adapters. Current default Map construction uses
Prefix/AA=1; List uses Positional/AA=0. A label with a slash is one opaque input
to the typed API. The older string-path resolver retains its compatibility
behavior; it is not the grammar for the new typed API.

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
and invalid layout/rule combinations are rejected. `wire/maltcid.ParseRoot`
decodes the descriptor; an engine additionally requires the selected AA rule
and profile implementation to be installed. Parsing an unknown AA is not
permission to execute it. No fallback derivation or backend inference is used.

| L | Layout | Permitted inputs |
| --- | --- | --- |
| 1 | Prefix | AA-derived 32-byte keys |
| 2 | Positional | AA=0, unsigned 64-bit indices |

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
and the new conformance corpus. A changed parameter set or cryptographic
encoding requires a new immutable profile ID even within the same algorithm.
IPA direct/compact/fast precomputation choices do not change profile identity.

`MALTVersionID=3` and the `CodecMaltMap*`/`CodecMaltList*` constants describe
frozen historical encodings. Use `RootVersion`, `NewRoot`, and `ParseRoot` for
current construction. A codec alone cannot identify a V0 Root's VC profile.

## AA registry and typed inputs

Inputs form a tagged union: `index`, `key`, `label`, or `system`. Index and
selector numbers use canonical decimal strings in JSON, avoiding JavaScript
precision loss. Key/label bytes use standard base64. Exactly the active union
field is present; numbers, padded decimal strings, unknown fields and mixed
union alternatives are rejected. Native keys are exactly 32 bytes.

| AA | Rule | Accepted inputs |
| --- | --- | --- |
| 0 | Direct | index to Positional coordinate; key to Prefix coordinate |
| 1 | BytesSHA256 | arbitrary label bytes or a registered system selector |
| 2 | UnixFSNameSHA256 | one valid UTF-8 name or a registered system selector |

AA=1 does not split slashes, normalize Unicode, fold case, reject empty labels
or interpret application names. Its derivation is:

```text
D = UTF8("malt:selector:sha256:0") || 0x00
label key  = SHA256(D || 0x00 || uvarint(byte_length) || label_bytes)
system key = SHA256(D || 0x01 || uvarint(selector_number))
```

All varints are minimal. Selector 1 denotes payload; other system selectors
are currently rejected. Explicit label bytes `@payload` and selector 1 are
different inputs with different derivations. The old Map string facade maps
`@payload` to selector 1 as a compatibility convention. Its direct-key facade
uses lowercase 64-character hex; the typed interface uses bytes.

AA=2 uses the same hash framing after validating one nonempty UTF-8 name,
excluding `/`, NUL, `.` and `..`. It specifies a MALT input profile useful to
a UnixFS adapter, not a universal filesystem/path standard. Application rules
such as reserved names, full paths and portable filename policy stay in `malt`.
Applications may canonicalize before submission or register a rule that fixes
canonicalization; MALT has no global label grammar.

IDs 0–2 cannot be replaced through registry registration. Extension IDs 3–255
are available only after explicit registration of their immutable rule. A
public allocation must include a Core PR with the exact accepted byte grammar,
derivation, namespace behavior, output width, rejection cases and conformance
vectors. Private deployments must coordinate IDs and implementations among all
writers, services and verifiers; a numeric ID does not download executable code.
Two different meanings must never share an ID. A registry rejects duplicates.

## Layout and internal node identity

Prefix routes over all 256 key bits (12 bits per KZG level, 8 per IPA level;
the final KZG digit is zero-padded). Terminal cells bind the full key and target
CID. An empty slot or a different full key proves absence. Native keys are not
rehash inputs. Collisions and duplicate coordinates are rejected. Cell encodings
are defined in `wire/maltcid/node_cells.go` and `auth/engine`; changing them must
not silently reuse an existing descriptor's interpretation.

Positional consumes dense indices `[0,count)`. Slot 0 contains structural
height/count/chunk-size/total-size metadata; the remaining `slots-1` cells are
entries or child references. Metadata is authenticated, including absence
beyond count and fixed-chunk range boundaries. **Positional has no system
bindings**. To associate payload/metadata content with a sequence, a containing
Prefix binds the sequence Root and the content CID as separate targets.

Internal references are `"MN" || 0x00 || byte(L) || multicommitment`.
They identify authentication nodes, not application vertices, and omit AA.
The root descriptor supplies input interpretation; an internal node is
interpreted with its layout and exact VC profile. Application-valued targets
retain complete Roots/CIDs, including the target Root's AA. Each explicit
traversal step uses the AA of the Root reached by the preceding verified step.

Equal normalized coordinates and targets can therefore reuse commitments and
internal nodes across AA modes, while the complete Roots remain distinct.
Caches validate the node identity, full vector and exact profile before reuse.
`EqualCommitment` does not establish interchangeable Root/query semantics.

## State, writes and proofs

The authenticated view contains coordinates, not original label preimages.
`engine.State` retains typed inputs for interpretation; applications or
Gateway-owned relation records preserve them for enumeration and future writes.
`ValidateState` derives coordinates again and checks them against root-bound
materialization. Canonicalization aliases authenticate the same key; they do
not prove an exact original spelling. Duplicate derived keys in one state fail.

`PrefixApply` and Positional replacement/append/truncation reuse unchanged
subtrees. Updates check expected bindings before exposing a result Root. I/O
failure may leave unreachable immutable nodes in the caller-owned store.
Candidate preparation and materialization do not publish or trust a Root and
do not prove a transition from a previous Root. A candidate's optional
`previous` field is storage lineage only.

The `malt.authentication/0` JSON contracts live in `protocol/authentication.go`
and `protocol/schemas/authentication*.schema.json`. Queries select a Root,
explicit typed traversal steps, and resolve/binding/range operation. Range
endpoints and structural uint64 metadata use decimal strings. Results contain
root-bound traversal and primitive evidence. A verifier uses the caller's
request, never a server-rewritten root or key, and performs no network lookup.
Unknown AA/profile combinations fail even for an empty traversal.

Candidates include original inputs and the complete reachable node vectors.
Validation rejects conflicting, missing and unreachable records before
materialization, and bounds logical expansion by the supplied binding count.
Service code should use `SnapshotBounded` when reconstructing untrusted state;
unbounded `Snapshot` is intended for callers that already bound their state.

## Compatibility and evidence

New default builders emit V0. Explicit V2/V3 compatibility constructors and
readers preserve historical bytes. Old writer views can be reconstructed into
V0 candidates; dependent parent bindings must be recomputed. Replacing a prefix
alone is not a migration. Payload CIDs remain reusable.

`conformance/authentication-v0.json` is a separate corpus. The frozen
Resolve/Read, Map-proof and client-root corpora retain their historical formats
and provenance. New and historical measurements must identify their exact
Core revision, profile and corpus. Browser release assets remain subject to
`malt-ts`'s exact published-Core lock and release conformance gate.

## SDK backend selection

`sdk/authentication` consumes a caller-supplied `auth/engine.Engine` for
preparation, execution, materialization, and verification. It imports no
concrete commitment backend. Applications that want the built-in verification
profiles may opt into `sdk/authentication/verifier.New`; that separate package
imports KZG and IPA. Backend-specific writer builds keep their selected backend
injected and must not import this convenience constructor.

# Compatibility Policy

MALT core is experimental and pre-v1. Exact tags should be pinned and unknown
profiles rejected.

## MALT Root version decision

The maintainer's 2026-09-12 [Root version policy](./root-versioning.md) requires
the self-describing Root refactor to use `V=0` throughout pre-production.
Only an explicit maintainer declaration of production readiness and go-live
permits `V=1`. Experimental incompatible changes must remain distinguishable
without automatically increasing this field. This does not renumber CIDv1,
operation profiles, package releases, storage schemas, or conformance corpora.

The existing flat and `V=2/3` formats described below are current/historical
implementation facts, not the future version-allocation rule. No executable
migration or old-root reinterpretation is performed by this policy update.

## Compatibility surfaces

| Surface | Status |
| --- | --- |
| Root `malt` typed facade | Experimental |
| `malt.resolve/v0alpha1` | Profiled; incompatible wire revisions require a new profile |
| `malt.read/v0alpha1` | Profiled; incompatible wire revisions require a new profile |
| `malt.map-proof/v0alpha1` | Experimental in v0.0.7-rc.1; exact Map membership and non-membership |
| `malt.update-view/v1` | Experimental in v0.0.7-rc.1; complete semantic closure |
| `stateful-complete-vectors-v1` | Experimental state profile required by the current update-view contract |
| `malt.semantic-intent/v1` | Experimental in v0.0.7-rc.1; output-free update intent |
| `malt.client-root-bundle/v1` | Experimental in v0.0.7-rc.1; exact-root submission, not a transition proof |
| `malt.client-root-materialization/v1` | Experimental in v0.0.7-rc.1; root-bound Map proof-serving witness, not a transition proof |
| `malt.writer-compute-result/v1` | Legacy browser-local bundle and next-view result; decode compatibility only |
| `malt.writer-compute-result/v2` | Experimental in v0.0.7-rc.1; browser-local bundle, Map materialization, and next-view result |
| `malt.materialization-receipt/v1` | Experimental in v0.0.7-rc.1; exact-bundle durability acknowledgement |
| ProofList JSON and proof semantics | Experimental, verifier-facing |
| Typed MALT root CIDs/codecs | Experimental, verifier-facing |
| `SegmentPath` projection | `/`-joined UTF-8 segments; experimental |
| Public Go semantic/materializer interfaces | Experimental source API |
| `sdk/writer` | Experimental source API for local complete-view client-root computation |
| `auth/observation` phases | Diagnostic source API; not wire data or proof evidence |
| `malt.artifact/v0alpha2` | Frozen v0.0.4 compatibility profile |
| ArcTable/KV/CAS implementations | Outside this module and not a core compatibility surface |
| CLI, daemon, HTTP routes, UnixFS | Outside this module |

The frozen artifact profile accepts only its released operation set. New
integrations use operation-specific resolve/read request/result pairs rather
than extending that union.

The `/v1` suffixes on the client-root profiles version those serialized
contracts. They do not mean that MALT, the Go module, or the source APIs have
reached a stable v1 release. These experimental profiles are included in
v0.0.7-rc.1 and are not part of the immutable v0.0.6 tag.

## Pre-v1 changes

Breaking Go package changes are allowed before v1 but must be explicit in
release notes. Changes to the following require matching tests, schemas, and
documentation in the same PR:

- profile identifiers or serialized request/result fields;
- ProofList fields, ordering, step kinds, or verification rules;
- root/CID encoding and commitment backend selection;
- canonical segment/arc validation;
- mutation, client-root, or receipt value semantics;
- payload-binding and measured-list evidence.

The root-codec compatibility boundaries are intentionally explicit:

- v0.0.6 emitted flat experimental codecs `0x300001` through `0x300004`.
  The structured decoder does not accept those roots. No migration layer is
  provided in this pre-v1 release; recreate experimental roots and their
  materialized proof-serving state.
- Structured version-2 codecs (`0x302...`) were introduced on `main` after
  v0.0.6. They are not v0.0.6 roots and remain readable and verifiable.
- Current constructors emit structured version-3 codecs (`0x303...`) in the
  project private-use `0x30VSBB` layout.

Typed-root constructors emit `MALTVersionID=3`.
Decoders explicitly retain v2 typed roots for read/proof compatibility and
reject every other unknown version, semantic ID, backend suite ID, and
combination; there is no heuristic fallback mapping.

Radix map profiles bind the entire internal tree to one typed-root version and
backend: v2 roots use v1 variable-length collision-bucket references, while v3
roots use v2 fixed-domain references. Readers recognize both profiles but reject
mixed-version internal children or a bucket reference that does not match its
parent profile. Only the v3/fixed-domain profile supports collision-bucket
non-membership proofs. Incremental map/list mutation APIs require the input root
version to match the semantics instance. The client writer handles v2 updates
by exactly replaying the complete v2 view, fully rebuilding it as v3, and
applying changes only to that v3 working root; direct partial v2-to-v3 mutation
is rejected so unchanged v2 child CIDs cannot leak into a v3 root.

Map non-membership proves only the absence of one exact keyed relation in a
Map. It does not prove List-index, graph-path, object, payload-byte, or remote
data absence, and ordinary `Read` retains its `ErrQueryNotFound` behavior.
There is no List non-membership API. Empty-slot and conflicting-leaf absence
work for compatible roots; collision-bucket non-membership requires the
version-3 fixed-domain bucket profile.

v0.0.6 intentionally removes application and deployment packages from this
module. Consumers of the former CLI/daemon/UnixFS/server/storage packages must
use `malt-client` or `gateway`; no forwarding packages are provided.

Payload CIDs remain governed by the selected CAS/CID rules. MALT proof
verification authenticates the CID relation, while the consuming client is
responsible for hashing returned bytes.

## Release notes

Every source release records:

- exact commit;
- verifier/profile/schema changes;
- Go source compatibility changes;
- reproducible test, vet, build, and WASM checks;
- known verification limitations.

Treat `main` as an integration branch, not a stable dependency.

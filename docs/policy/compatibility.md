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

Current construction and verification accept only self-describing V0 Roots.
Historical flat and V2/V3 formats are rejected. The current writer does not
migrate old update views; recreate experimental state as described in the
[pre-beta API cleanup](../changes/prebeta-cleanup.md).

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
| `malt.client-root-bundle/v2` | Experimental in v0.0.7-rc.1; exact-root submission, not a transition proof |
| `malt.client-root-materialization/v1` | Experimental in v0.0.7-rc.1; root-bound Map proof-serving witness, not a transition proof |
| `malt.writer-compute-result/v1` | Retired; rejected by the current transaction contract |
| `malt.writer-compute-result/v3` | Experimental in v0.0.7-rc.1; browser-local bundle, Map materialization, and next-view result |
| `malt.materialization-receipt/v2` | Experimental in v0.0.7-rc.1; exact-bundle durability acknowledgement |
| ProofList JSON and proof semantics | Experimental, verifier-facing |
| Typed MALT root CIDs/codecs | Experimental, verifier-facing; current self-describing V0 only |
| `SegmentPath` projection | `/`-joined UTF-8 segments; experimental |
| Public Go semantic/materializer interfaces | Experimental source API |
| `sdk/writer` | Experimental source API for local complete-view client-root computation |
| `auth/observation` phases | Diagnostic source API; not wire data or proof evidence |
| `malt.artifact/v0alpha2` | Retired; its package, schemas, and verifier entry points are removed |
| ArcTable/KV/CAS implementations | Outside this module and not a core compatibility surface |
| CLI, daemon, HTTP routes, UnixFS | Outside this module |

The historical artifact profile and its released operation set remain
documented in the [retired profile reference](../spec/artifacts.md). Current
integrations use operation-specific resolve/read/Map-proof request/result
pairs and their local verifiers.

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

- Current constructors and readers use the self-describing `0x30VLAA`
  format with `RootVersion=0`. The codec selects the layout and input rule;
  the identity-wrapped multicommitment selects the exact VC profile.
- The v0.0.6 flat experimental codecs `0x300001` through `0x300004`, the later
  structured V2 codecs (`0x302...`), and the historical V3 codecs (`0x303...`)
  are unsupported. Their constructors, readers, and replay graphs are removed.
- Recreate old experimental state and its proof-serving materialization with
  the current implementation, then recompute dependent parents. A changed CID
  prefix does not convert old node or proof encodings.

Root parsing validates canonical framing, `V=0`, the layout, and the exact VC
profile and commitment width. Operations also require the selected input rule
and VC implementation to be registered. Unsupported combinations fail closed;
there is no heuristic fallback. See
[authentication inputs and Roots](../spec/authentication-inputs.md).

Historical collision-bucket layouts and their proof envelopes are retired.
Current Prefix and Positional evidence uses `malt.binding/0`, as specified in
[commitment and proof encoding](../spec/commitment-proof-encoding.md).

Map non-membership proves only the absence of one exact keyed relation in a
Map. It does not prove List-index, graph-path, object, payload-byte, or remote
data absence, and ordinary `Read` retains its `ErrQueryNotFound` behavior.
The Map-proof operation does not provide List non-membership. Current Prefix
absence terminates at a proved empty slot or a routed leaf for a different
key. Typed authentication has its own Positional out-of-range evidence rules.

Current conformance corpora are Resolve/Read v3, Map-proof v2, client-root v4,
and typed authentication/0. Historical corpus bytes and schema identifiers
remain in Git history; current loaders reject those retired corpus versions.
See [conformance corpora](../spec/conformance-corpora.md).

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

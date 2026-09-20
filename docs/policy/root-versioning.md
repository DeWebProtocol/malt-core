# MALT Root Version Policy

Decision date: 2026-09-12.
Status: maintainer-directed policy for the self-describing Root refactor;
current construction and verification use V0; V2/V3 readers are retired.

## Production-readiness gate

The MALT Root version field `V` must remain `0` throughout pre-production
development, including incompatible experimental refactors and experimental
source or SDK releases. Do not increment `V` for each wire-format change.

Set `V=1` only after the maintainer explicitly declares that MALT is going
live and is production ready. A tag, GitHub Release, successful test run,
paper submission, deployment, or agent judgment does not constitute that
declaration. The implementation of the `V=1` transition follows that explicit
decision; it must not be scheduled or performed automatically.

This policy governs the MALT Root field only. CIDv1's container version,
package SemVer, operation-profile suffixes, conformance-corpus versions,
storage-schema versions, and VC profile IDs are separate identifiers. Do not
renumber those values to `0` as a consequence of this policy.

## Experimental changes while V remains zero

`V=0` identifies the pre-production family; it does not, by itself, establish
compatibility between every experimental build.

- Exact VC profiles must fix their parameters, encodings, and verification
  rules. A different cryptographic configuration receives a distinct profile
  ID; execution-only performance options do not change Root identity.
- An incompatible input or layout interpretation must remain distinguishable
  through explicitly defined identifiers or framing. It must not silently
  reuse the same complete Root descriptor for a different meaning.
- Pin source revisions, protocol profiles, and conformance corpora in
  experimental artifacts. An artifact's provenance does not replace the
  Root's own interpretation rules.
- Unknown or unsupported combinations fail closed. An experimental migration
  must explicitly choose rejection, reconstruction, or a specified reader;
  changing `V` is not the default way to resolve that boundary.

The implemented framing is specified in [authentication inputs and Roots](../spec/authentication-inputs.md)
and tracked by [MIP-1014](../mips/mip-1014-self-describing-roots.md).

## Existing experimental encodings

At historical Core commit `c90b4d35ec95003b14422546b777fbf9ada2b0c7`, constructors
emitted the older `0x30VSBB` format with `MALTVersionID=3`, and decoders
retained explicit version-2 compatibility. Earlier experiments also used
version-1 structured roots and flat codecs `0x300001` through `0x300004`.
None of those historical numbers declares production readiness.

Current constructors and readers accept only self-describing `RootVersion=0`
Roots. The pre-beta cleanup removes the V2/V3 constructors, readers, and
automatic writer-view migration. Historical source and corpus bytes remain
in Git history with their original identities; old flat and V2/V3 codecs are
not aliases of the current format.

Recreate old experimental state with the current implementation and recompute
dependent parents. Replacing a Root prefix alone does not migrate the state.
Payload CIDs can be reused. Historical release notes retain their original
dates and release-specific claims. See the
[current Root specification](../spec/authentication-inputs.md) and
[pre-beta migration guidance](../changes/prebeta-cleanup.md).

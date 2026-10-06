# Security Policy

MALT Core is an experimental, application-neutral authentication SDK. Its
public APIs, ProofList schemas and wire formats may change. It is not
production-ready.

Security reports are still important because the project deals with proof
verification, authenticated graph structures, commitment backends, and
untrusted caller-supplied evidence.

## Supported Versions

| Version | Security support |
| --- | --- |
| `main` | Best-effort review of current integration code |
| `v0.0.10-rc.3` | Current experimental Core release candidate |
| Earlier experimental versions | Historical contracts; no compatibility or backport guarantee |

This release snapshot was checked on 2026-10-06. Pin an exact published release
when evaluating Core; `main` is an integration branch. The current release is
[`v0.0.10-rc.3`](https://github.com/DeWebProtocol/malt-core/releases/tag/v0.0.10-rc.3),
at `6f16b13f3abe9cbd0992e83e1457663935e5a72f`.

Security fixes may require breaking API, proof, Root or wire-format changes.
The [compatibility policy](docs/policy/compatibility.md) defines the current
contracts and latest-only pre-beta migration policy. Current queries use
`malt.authentication/3` and self-describing V0 Roots; the retired Map-proof,
Resolve/Read and client-root interfaces are not supported compatibility paths.
The optional `sdk/object` constructors in rc.3 use the current authentication
contracts and do not introduce a new wire format.

## Reporting a Vulnerability

Do not open a public issue for a suspected vulnerability.

Current security contact: security@deweb.world

Preferred reporting path:

1. Use GitHub private vulnerability reporting or open a private GitHub Security
   Advisory for this repository.
2. If private vulnerability reporting is not enabled yet, contact
   security@deweb.world privately with `SECURITY` in the subject or opening
   line.
3. Include a short description, reproduction steps, affected commit or version,
   and any proof-of-concept data needed to reproduce the issue.

Maintainers should acknowledge reports within 7 days when practical and keep the
reporter updated on triage, fix, and disclosure timing.

## Useful Report Categories

High-value areas include:

- ProofList verification accepting invalid evidence
- Root, label traversal, operation, range, or target mismatches in query verification
- malformed Root descriptors, unknown profiles, or noncanonical wire values accepted by decoders
- inconsistent candidate state, ordered batches, or exact receipts accepted by contract validation
- incorrect Object commitments, snapshot isolation, or graph deltas
- commitment or proof backends accepting malformed or inconsistent inputs
- dependency vulnerabilities with reachable impact

Include the exact request, expected Root and query, returned evidence, and
backend/profile when relevant. A materialization receipt is operational
acknowledgement, not a portable state-transition proof or trusted-root acceptance.

## Current Experimental Limits

Core does not own:

- head publication and freshness
- multi-writer merge or arbitration
- tenant isolation, quota, pinning, or garbage collection
- daemon, gateway, CAS, UnixFS, or application-layer policy
- browser Worker lifecycle, WASM compilation, or distributed browser assets

Those concerns belong to the runtime, Gateway, malt-ts, or an application.
Report a suspected vulnerability privately to the owning repository, or use
the contact above when ownership is unclear. Core proof verification binds
evidence to a caller-selected Root and query; applications must also verify
fetched payload bytes against authenticated CIDs and select their own trusted
Roots. Stable API compatibility and production security guarantees remain
outside this experimental release policy.

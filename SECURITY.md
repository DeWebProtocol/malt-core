# Security Policy

MALT is an experimental reference implementation. It is runnable end to end, but
its public APIs, ProofList schemas, wire formats, and deployment policies may
change. It is not production-ready.

Security reports are still important because the project deals with proof
verification, authenticated graph structures, commitment backends, and
untrusted caller-supplied evidence.

## Supported Versions

| Version | Security support |
| --- | --- |
| `main` | Best-effort review of current integration code |
| `v0.0.7-rc.3` | Current experimental release candidate |
| `v0.0.7-rc.2` | Previous experimental release candidate |
| `v0.0.6` | Previous non-prerelease experimental source release |
| `v0.0.5` and earlier | Not supported |

MALT remains pre-`v1.0.0` and experimental. Security fixes may require
breaking API, proof, root, or wire-format changes. Consumers evaluating the
current typed-root and Map-proof contracts should pin `v0.0.7-rc.3` rather
than depend on `main`. Consumers remaining on v0.0.6 must not assume its flat
roots are wire-compatible with this release candidate.

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
- root, canonical query, operation, or target mismatches in resolve/read verification
- payload bytes accepted without binding them to an authenticated CID
- invalid graph transitions accepted by resolve, read, or mutation algorithms
- commitment or proof backends accepting malformed or inconsistent inputs
- dependency vulnerabilities with reachable impact

## Current Experimental Limits

The current implementation does not provide production guarantees for:

- head publication and freshness
- multi-writer merge or arbitration
- tenant isolation, quota, pinning, or garbage collection
- daemon, gateway, CAS, UnixFS, or application-layer policy
- stable public API compatibility

Reports in those areas are useful, but they may be handled as design issues
rather than confidential vulnerabilities unless they expose a concrete bug in
the current implementation.

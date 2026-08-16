# MALT Improvement Proposals

This directory tracks MALT Improvement Proposals, or MIPs. The structure is
inspired by Ethereum's EIP process, but scaled down for this project. A MIP is
not an implementation TODO by default. It becomes TODO work only after the
maintainer accepts it for the implementation mainline and a phased plan exists.

[`mip-1.md`](mip-1.md) is the Living Meta MIP for this process. Standards
Track and Informational MIPs start at `mip-1001.md` unless the maintainer
assigns a different range.

## MIP Header

Each MIP starts with YAML front matter:

```yaml
mip: 1001
title: Short title
description: One sentence summary.
author: MALT maintainers
status: Draft
type: Standards Track
category: Core
created: 2026-05-25
requires: none
replaces: none
```

Use `type: Standards Track` for semantic/API/implementation proposals, `type:
Meta` for process proposals, and `type: Informational` for non-normative design
notes. For Standards Track MIPs, use categories such as `Core`, `Interface`,
`Evaluation`, or `Tooling`.

Do not add a separate `Summary` section before `Abstract`; use `description`
for the one-sentence summary and `Abstract` for the short technical summary.

Use [`mip-template.md`](mip-template.md) when drafting a new MIP.

## MIPs Versus Reference Specs

MIPs are proposal and decision records. They should state the change boundary,
motivation, selected direction, alternatives, compatibility impact, security
impact, and implementation planning state.

Long-lived protocol definitions, field tables, wire formats, JSON artifact
shapes, and benchmark record rules belong in:

- [`../spec/`](../spec/) for protocol, API, proof, receipt, artifact, and wire
  references
- [`../evaluation.md`](../evaluation.md) for routing executable evaluator work
  to `malt-evaluation` and paper interpretation to the research repository

A MIP may link to those reference docs and propose changing them, but it should
not become the only copy of a schema or specification.

## Status Lifecycle

| Status | Meaning | Planning rule |
|---|---|---|
| Draft | Open candidate, still being shaped. | Not implementation work |
| Review | Ready for maintainer review. | Not implementation work |
| Last Call | Expected to be accepted unless objections appear. | Not implementation work |
| Accepted | Approved to enter the implementation mainline. | Create a GitHub issue, PR plan, or repository planning note |
| Planned | Accepted and backed by a phased implementation plan. | Track the phase plan in the implementation repository |
| In Progress | Implementation branch or PR is active. | Track active work in the PR or linked issue |
| Final | Implemented, merged, and current docs updated. | Keep the MIP history and close the linked implementation work |
| Stagnant | No longer actively considered. | Not implementation work |
| Withdrawn | Deliberately abandoned. | Not implementation work |
| Superseded | Replaced by another MIP. | Link replacement in both MIPs |

## Index

| MIP | Status | Type | Category | Summary |
|---|---|---|---|---|
| [MIP-1](mip-1.md) | Living | Meta | Process | Define the MALT Improvement Proposal process and document format. |
| [MIP-1001](mip-1001-semantic-object-and-arc-terminology.md) | Draft | Standards Track | Core | Define graph root, semantic object, payload, outgoing arc, map relation, and list child-reference terminology. |
| [MIP-1002](mip-1002-writer-receipt-accounting.md) | Draft | Standards Track | Interface | Decide how writer receipts support storage, indexing, accounting, and benchmark reporting. |
| [MIP-1003](mip-1003-prooflist-verification-schema.md) | Review | Standards Track | Core | Formalize ProofList verifier contract, body/header binding, omission behavior, and range-body verification. |
| [MIP-1004](mip-1004-resolve-prooflist-artifact-schema.md) | Final | Standards Track | Interface | Record the frozen v0.0.4 resolve/prove/verify artifact profile and schemas. |
| [MIP-1005](mip-1005-kzg-map-label-domain.md) | Final | Standards Track | Core | Record the canonical binding-CID slot model for storage-free map commitment primitives. |
| [MIP-1006](mip-1006-variable-size-measured-list-evidence.md) | Draft | Standards Track | Core | Specify a future range-addressable list model for variable-size children. |
| [MIP-1007](mip-1007-incremental-add-root-optimization.md) | Draft | Standards Track | Tooling | Explore path-local incremental add for very large existing roots. |
| [MIP-1008](mip-1008-semantic-reachability-demo.md) | Draft | Informational | Evaluation | Define a small demo for reverse, cross-object, and multi-view relations. |
| [MIP-1009](mip-1009-benchmark-proof-reporting.md) | Draft | Standards Track | Evaluation | Define paper-facing proof, receipt, and metrics reporting across benchmark suites. |
| [MIP-1010](mip-1010-data-authentication-core-boundary.md) | Superseded | Standards Track | Core | Historical in-module package split, replaced by MIP-1013 and the v0.0.6 repository boundary. |
| [MIP-1011](mip-1011-arc-authentication-core-contract.md) | Final | Standards Track | Core | Define the portable arc-level `Read`/`Apply`/`VerifyRead` contract introduced in `v0.0.3`. |
| [MIP-1012](mip-1012-segment-path-resolution.md) | Final | Standards Track | Core | Define segment arrays, proof-carrying arc composition, and existential resolution. |
| [MIP-1013](mip-1013-client-gateway-core-boundary.md) | Final | Standards Track | Core | Separate client trust, gateway execution, CAS payload, and UnixFS application-model responsibilities. |

## Promotion Protocol

1. Keep the proposal process itself in MIP-1.
2. Keep open design questions in Draft MIPs.
3. Move a MIP to Review only when its proposal boundary and rationale are
   concrete enough for maintainer judgment. Reference-spec details may live in
   `../spec/` or checked-in protocol schema files and be linked from the MIP.
4. Move a MIP to Accepted only after maintainer approval.
5. For Accepted MIPs, create a GitHub issue, PR plan, or repository planning
   note that names the implementation owner and review boundary.
6. Have a model write a phased implementation plan that names concrete files,
   tests, verification gates, and expected PR boundaries.
7. Move the MIP to `Planned` or `In Progress` only after the plan or
   implementation branch exists.
8. When implementation merges, update the MIP history, update current status
   docs, and close the linked implementation work.

## Current Implementation Baseline

These MIPs were migrated from the previous research-documentation repository to
`DeWebProtocol/malt-core` as the implementation-bound proposal source of truth. The
initial migrated set was originally based on implementation main around commit
`c827af2`, including PR #74 graph/resolver/writer/layout boundary work, PR #73
stale API/proof type cleanup, PR #75 implementation-doc alignment, subsequent
dependency upgrades (#87-#92), and open-source preparation.

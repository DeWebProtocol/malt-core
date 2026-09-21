---
mip: 1012
title: Segment Path Resolution
description: Define canonical MALT segments, proof-carrying arc composition, and existential resolution semantics.
author: MALT maintainers
status: Final
type: Standards Track
category: Core
created: 2026-07-12
requires: 1001, 1011
replaces: none
---

## Abstract

MALT accepts application-neutral segment arrays and composes authenticated arcs
without requiring clients to know arc boundaries. `/` is the canonical textual
projection, while transports and applications remain free to map their own path
syntax to segments.

## Motivation

If `root1` authenticates arc `a/b` to `root2`, `root2` authenticates `c` to
`root3`, and `root3` authenticates `d`, a client should submit
`["a", "b", "c", "d"]`. Requiring `["a/b", "c", "d"]` would leak the
current graph's arc partitioning into every client and would require a separate
untrusted discovery request before resolution.

At the same time, the core should not parse JavaScript properties, filesystem
paths, URLs, or other application grammars. Those syntaxes have different
escaping and conflict rules.

## Decision

- A MALT path is an ordered array of non-empty UTF-8 segments.
- A segment cannot contain `/`; joining segments with `/` is the canonical
  textual map-coordinate projection.
- The empty array denotes the caller-supplied root.
- Transports carry segments directly where possible. Slash URLs are one
  transport mapping, not the canonical API type.
- The resolver may discover an arc that consumes multiple leading segments and
  continue from its authenticated target until all requested segments are
  consumed.
- The reference resolver prefers the longest available prefix at each root.
- Verification proves the returned complete derivation. It does not prove that
  the chosen prefix or derivation was longest, shortest, unique, or otherwise
  application-preferred.
- When multiple valid derivations exist, accepting any verified derivation is
  normal core behavior; a client may add an application-specific preference.

The normative rules and examples live in
[`docs/spec/segment-paths.md`](https://github.com/dewebprotocol/malt-core/blob/a4526f8751db403eaa2e1a7ac6add00b70ff2933/docs/spec/segment-paths.md).

## Rationale

This boundary gives clients a stable interface without making application
syntax part of MALT. Candidate lookup remains optimizable and untrusted;
correctness comes from verification of the ordered arc chain relative to the
trusted root.

Requiring a non-membership proof for every longer candidate would strengthen
the result into a maximality claim that the application does not need. It would
also enlarge the proof and couple verifier semantics to one execution policy.

## Security Considerations

Alternative valid derivations can return different authenticated targets if an
application creates overlapping relations. This is not proof forgery: each
accepted result still proves its own root-to-target derivation. Applications
that require deterministic namespace behavior may impose and validate their
own overlap policy; MALT core does not require one.

Transport adapters must not silently apply dot-segment or whitespace
normalization to the canonical segment contract. If a transport reserves such
values, it must reject or reversibly encode them before calling core.

## History

- 2026-07-12: Accepted and implemented for `v0.0.4`.

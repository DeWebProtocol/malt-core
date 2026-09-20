---
mip: 1003
title: ProofList Verification Contract
description: Formalize ProofList step semantics, body/header binding, proof omission, and range-body verification.
author: MALT maintainers
status: Review
type: Standards Track
category: Core
created: 2026-05-25
requires: none
replaces: none
---

## Abstract

This MIP formalizes the verifier contract described in
[`docs/spec/prooflist-format.md`](https://github.com/dewebprotocol/malt-core/blob/a4526f8751db403eaa2e1a7ac6add00b70ff2933/docs/spec/prooflist-format.md), including map
traversal, terminal `@payload`, blob binding, measured-list `list_range`
evidence, proof omission, and returned-body binding.

## Motivation

The implementation verifies ProofList evidence through portable
`auth/verifier`; `graph/verifier` is a thin reference-runtime adapter. The
paper-facing contract still needs a clear review boundary so readers can
distinguish ProofList verification from HTTP body-byte binding and JSON shape
validation.

## Specification

The current ProofList reference lives in
[`docs/spec/prooflist-format.md`](https://github.com/dewebprotocol/malt-core/blob/a4526f8751db403eaa2e1a7ac6add00b70ff2933/docs/spec/prooflist-format.md). The `v0.0.3`
source release records this review boundary:

- ordered path traversal is verifier-facing and implemented by
  `auth/verifier`;
- terminal `@payload` binding is a terminal proof step and must not be followed
  by later traversal steps;
- map, list-index, and measured-list `list_range` structure evidence is
  verified through verification-only backends selected from typed roots;
- transport choices do not change the verifier contract for results that are
  returned;
- returned byte-range body bytes are not authenticated by ProofList alone and
  must be bound to authenticated segment CIDs by the consuming client.

This MIP does not promote ProofList JSON to a stable cross-release schema. It
records the current verifier contract for review before a stable API line.

## Rationale

Current code evidence:

- `auth/proof/prooflist/prooflist.go` defines ProofList shape.
- `auth/verifier` verifies ordered traversal, typed query binding, and map/list
  evidence without runtime or storage lookup.
- `graph/verifier/verifier.go` adapts reference runtime semantics to that
  portable verifier.
- `protocol` carries operation-specific ProofLists across transports.
- `DeWebProtocol/gateway` exposes diagnostic verification and generic
  resolve/read/CAS transport.
- `DeWebProtocol/malt-client` and Web compose UnixFS evidence and bind returned
  range bytes to authenticated segment CIDs.

## Backwards Compatibility

The `v0.0.3` `v0alpha1` contract remains experimental. If field names,
evidence labels, or verifier behavior change before a stable release, the same
change must update `docs/spec/prooflist-format.md`, tests, CLI/HTTP examples,
and release notes.

## Security Considerations

This MIP is security-sensitive because it defines what a client actually
verifies. ProofList verification must reject forged paths, malformed list
metadata, branch jumps, and traversal after terminal payload bindings. Range
body acceptance must also reject shifted ranges, segment CID mismatches, short
segment data, and tampered returned bytes.

## Implementation Plan

For the current review pass:

- keep the durable field reference in `docs/spec/prooflist-format.md`;
- keep reusable verifier orchestration and verification-only backends in
  `auth/verifier`;
- keep `graph/verifier` as a compatibility adapter only;
- keep range body-byte binding in the application client;
- run core verifier, gateway, client, and Web validation before tagging.

## History

- 2026-05-25: Created from the previous open TODO list.
- 2026-06-25: Moved current ProofList shape and transport rules to
  `docs/spec/prooflist-format.md`; this MIP tracks formal acceptance of the
  verifier contract.
- 2026-07-06: Updated for `graph/verifier` extraction and the UnixFS range-body
  verifier; moved to Review for maintainer judgment.
- 2026-07-11: Moved trust-critical orchestration and built-in KZG/IPA proof
  verification to portable `auth/verifier`; retained `graph/verifier` as an
  adapter.
- 2026-07-14: Routed transport to gateway and UnixFS/body binding to clients
  for the SDK-only v0.0.6 boundary.

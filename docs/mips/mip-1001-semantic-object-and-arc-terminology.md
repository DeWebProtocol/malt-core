---
mip: 1001
title: Semantic Object And Arc Terminology
description: Define graph root, semantic object, payload, outgoing arc, map relation, and list child-reference terminology.
author: MALT maintainers
status: Draft
type: Standards Track
category: Core
created: 2026-05-25
requires: none
replaces: none
---

## Abstract

This MIP proposes adopting the terminology in
[`docs/spec/semantic.md`](https://github.com/dewebprotocol/malt-core/blob/a4526f8751db403eaa2e1a7ac6add00b70ff2933/docs/spec/semantic.md) for graph roots, semantic
objects, payloads, outgoing arcs, map relations, list child references, and CAS
blobs.

## Motivation

The current implementation separates semantic abstractions from graph runtime
composition: `map` and `list` own semantic behavior, while `graph` composes
resolver and writer ports. The paper needs vocabulary that preserves this
boundary and avoids turning implementation helpers into semantic definitions.

## Specification

Adopt [`docs/spec/semantic.md`](https://github.com/dewebprotocol/malt-core/blob/a4526f8751db403eaa2e1a7ac6add00b70ff2933/docs/spec/semantic.md) as the implementation
reference for semantic terminology. That reference classifies:

- semantic object
- graph root
- payload
- outgoing arc
- map relation
- list child reference
- CAS blob

This MIP remains the proposal record for accepting or revising that vocabulary.
The reference document owns the current term definitions.

## Rationale

Current code evidence:

- `auth/arcset` owns canonical path and arcset representation.
- `auth/semantic/mapping` defines map semantics.
- `auth/semantic/list` defines indexed child-reference semantics.
- `graph` composes resolver and writer ports.
- UnixFS is an application model/profile implemented by
  `DeWebProtocol/malt-client` and the browser client.

## Backwards Compatibility

This MIP starts as documentation and naming work. Code renames, if any, require
a separate accepted MIP or implementation plan.

## Security Considerations

Terminology must not imply that ArcTable, local storage placement, or runtime
graph state is a trust root. Client verification remains rooted in semantic
proofs and published roots.

## Implementation Plan

No implementation work is approved while this MIP is Draft. If accepted, update
`README.md`, `ARCHITECTURE.md`, `docs/spec/semantic.md`, and any code comments
that use conflicting terminology.

## History

- 2026-05-25: Created from the previous open TODO list.
- 2026-06-25: Moved term definitions to `docs/spec/semantic.md`; this MIP now
  tracks terminology adoption rather than duplicating the glossary.

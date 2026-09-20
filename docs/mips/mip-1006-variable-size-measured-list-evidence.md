---
mip: 1006
title: Variable-Size Measured List Evidence
description: Specify a future range-addressable list model for variable-size children.
author: MALT maintainers
status: Draft
type: Standards Track
category: Core
created: 2026-05-25
requires: 1003
replaces: none
---

## Abstract

This MIP proposes a future measured-list proof model for variable-size child
segments. The current fixed-width measured-list behavior is documented in
[`docs/spec/semantic.md`](https://github.com/dewebprotocol/malt-core/blob/a4526f8751db403eaa2e1a7ac6add00b70ff2933/docs/spec/semantic.md) and
[`docs/spec/prooflist-format.md`](https://github.com/dewebprotocol/malt-core/blob/a4526f8751db403eaa2e1a7ac6add00b70ff2933/docs/spec/prooflist-format.md).

## Motivation

Current range evidence is fixed-width and sufficient for the current UnixFS
large-file path. A variable-size list would need each range-addressable child
slot to authenticate both child size and CID, while root metadata
authenticates child count and total size.

## Specification

The current implementation uses fixed-width measured-list evidence. If this
proposal is accepted, the future variable-size model should define:

- child descriptor shape
- root metadata
- range selection algorithm
- proof payload contents
- verifier checks

It should also describe how the new model coexists with or replaces the
current fixed-width `list_range` proof shape.

## Rationale

Current code evidence:

- `auth/semantic/list` defines list semantics and measured range
  interfaces.
- `auth/semantic/list/tree` supports fixed-width measured range
  evidence.
- `DeWebProtocol/malt-client` composes `list_range` ProofList steps with
  metadata and segment CIDs.

## Backwards Compatibility

The fixed-width measured-list path should remain valid unless the accepted MIP
explicitly replaces it.

## Security Considerations

The proof must bind both segment size and CID. A verifier must reject any range
proof that shifts byte boundaries while preserving the same segment CIDs.

## Implementation Plan

No implementation work is approved while this MIP is Draft. If accepted, a
phase plan should cover list backend changes, ProofList updates, server
verification, reference spec updates, and evaluation schemas.

## History

- 2026-05-25: Created from the previous open TODO list.
- 2026-06-25: Clarified that current fixed-width measured-list evidence is a
  reference-spec topic and this MIP tracks only the future variable-size model.

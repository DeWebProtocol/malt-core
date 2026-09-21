---
mip: 1002
title: Writer Receipt Accounting
description: Decide how writer receipts support storage, indexing, accounting, and benchmark reporting.
author: MALT maintainers
status: Draft
type: Standards Track
category: Interface
created: 2026-05-25
requires: none
replaces: none
---

## Abstract

This MIP proposes whether the writer receipt meanings documented in
[`docs/spec/writer-receipts.md`](https://github.com/dewebprotocol/malt-core/blob/a4526f8751db403eaa2e1a7ac6add00b70ff2933/docs/spec/writer-receipts.md) should become a
stable API and evaluation accounting contract.

## Motivation

The writer already returns mutation receipts, and HTTP mutation responses expose
receipt-derived counts. The paper and benchmark pipeline need a stable meaning
for those counts before treating them as evidence.

## Specification

The current receipt reference lives in
[`docs/spec/writer-receipts.md`](https://github.com/dewebprotocol/malt-core/blob/a4526f8751db403eaa2e1a7ac6add00b70ff2933/docs/spec/writer-receipts.md). This MIP should
decide whether to accept that reference as:

- API contract
- storage and indexing accounting input
- benchmark reporting input
- operational diagnostics only

Root publication metadata remains outside MALT core unless a future accepted
proposal explicitly adds it.

## Rationale

Current code evidence:

- `graph/writer` owns semantic mutation execution and receipts.
- `api/http/types.go` exposes `SemanticMutationResponse`.
- `DeWebProtocol/gateway` maps writer receipts into managed HTTP responses.
- `DeWebProtocol/malt-client` defines UnixFS application mutation plans.

## Backwards Compatibility

Existing HTTP response fields should remain compatible unless the accepted MIP
explicitly changes the API and defines a migration path.

## Security Considerations

Receipt fields are not correctness proofs. They must not be described as
verification evidence unless tied to a ProofList or commitment proof.

## Implementation Plan

No implementation work is approved while this MIP is Draft. If accepted, a
phase plan should cover `graph/writer`, `api/http`, server routes, eval schemas,
summary generation, `docs/spec/writer-receipts.md`, and tests.

## History

- 2026-05-25: Created from the previous open TODO list.
- 2026-06-25: Moved receipt field definitions to
  `docs/spec/writer-receipts.md`; this MIP now tracks stabilization and
  accounting policy.

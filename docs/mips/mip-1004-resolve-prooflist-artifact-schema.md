---
mip: 1004
title: Resolve, Prove, And Verify Artifact Schema
description: Record the frozen v0.0.4 transport-neutral artifact compatibility profile.
author: MALT maintainers
status: Final
type: Standards Track
category: Interface
created: 2026-05-25
requires: 1003, 1011, 1012
replaces: none
---

## Abstract

MALT `v0.0.4` publishes the `malt.artifact/v0alpha2` contract for `resolve`,
`prove`, and `verify`. The contract binds a trusted root, typed query, target,
optional measured-range segments, and ProofList in one transport-neutral
envelope with checked-in JSON Schemas.

## Motivation

The `v0.0.3` facade stabilized the in-process root/query/result binding but the
CLI resolve DTO and bare ProofList did not carry a version discriminator or a
complete self-describing request binding. Gateways, daemons, and cross-language
SDKs need one shared contract rather than independently reconstructing those
bindings from routes or headers.

## Decision

- The Go package is the unversioned `artifact`; package names do not contain
  release or alpha suffixes.
- Every serialized request, artifact, and result carries the exact profile
  `malt.artifact/v0alpha2`.
- `resolve` accepts a root plus canonical MALT segments and returns one complete
  proof-carrying derivation.
- `prove` accepts exactly one primitive `map_key`, `list_index`, or
  `list_range` query.
- `verify` validates the envelope bindings before portable proof verification.
- JSON Schemas are checked in under `artifact/schemas`, embedded in the Go
  package, and identified by stable `$id` values.
- Schema validation remains distinct from cryptographic and semantic proof
  verification.
- The operation set and field schema are frozen. In particular,
  `resolve_payload` was not published by v0.0.4 and cannot be added under the
  same profile discriminator.
- Operation-specific resolve/read contracts may supersede this envelope for
  new integrations while its released schema remains decodable.

The normative field and verification rules live in
[`docs/spec/artifacts.md`](https://github.com/dewebprotocol/malt-core/blob/a4526f8751db403eaa2e1a7ac6add00b70ff2933/docs/spec/artifacts.md).

## Compatibility

This is an opt-in profiled contract. Consumers must reject unknown profiles.
An incompatible pre-`v1` revision will publish a new profile value and schemas
instead of silently changing `v0alpha2`.

## Security Considerations

A gateway-produced artifact is untrusted until verified relative to a
caller-accepted root. JSON Schema validation only checks shape. Verification
must also bind the root, query, target, range segments, ProofList ordering, and
all backend evidence.

## History

- 2026-05-25: Opened the question of stable resolve and ProofList schemas.
- 2026-07-11: Deferred named schemas from the `v0.0.3` `v0alpha1` profile.
- 2026-07-12: Finalized the profiled resolve/prove/verify contract and schemas
  for `v0.0.4`.
- 2026-07-13: Froze the published operation set and moved new integrations to
  operation-specific resolve/read contracts; payload selection is represented
  by an explicit `@payload` resolve segment.

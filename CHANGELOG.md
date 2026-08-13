# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.0.7-rc.3] - 2026-08-13

This release-candidate delta removes the remaining KZG setup bottleneck and
optimizes internal KZG commitment, opening, and verification execution without
changing externally observable commitment or wire semantics.

### Added

- Add a verification-only KZG constructor that loads only the canonical G1
  generator and the two G2 opening-key points.
- Add reproducibly generated, committed verifier and Writer setup assets
  derived from the exact `go-kzg-4844 v1.1.0` trusted setup.
- Add a generation test that revalidates all 4096 retained G1 points and both
  retained G2 points, then byte-compares the derived assets with the committed
  copies.

### Changed

- Replace runtime JSON parsing and decompression of all 4096 KZG Lagrange G1
  points with build-time validated canonical coordinates for Writer startup.
- Replace the internal KZG commitment, opening, and verification execution path
  with equivalent gnark public operations over the validated setup assets.
- Use the verification-only KZG scheme in the default portable and SDK
  verifier registries.

### Compatibility

- These changes do not alter MALT roots, CIDs, KZG parameters, commitments,
  proofs, transcripts, ProofLists, receipts, schemas, or wire encodings.
- KZG commitments and openings remain byte-for-byte interoperable with the
  pinned `go-kzg-4844 v1.1.0` implementation.

## [0.0.7-rc.2] - 2026-08-10

This release-candidate delta completes the browser Verifier/Writer separation
introduced in v0.0.7-rc.1.

### Added

- Add explicit IPA `direct`, `compact`, and `fast` committer profiles while
  preserving one parameter set, typed roots, commitments, and proof encoding.
- Add verifier-only IPA initialization without committer fixed-base tables.
- Export the canonical IPA parameter-set identifier and digest for release
  provenance.
- Add `malt.web-writer.provenance/v3` for split Writer artifacts and the Core
  invariants of one runtime per controller and exact backend/profile targeting.
- Add reproducible, content-addressed Verifier and Writer WASM release bundles
  whose filenames bind the full asset-set and archive digests and whose served
  paths include the full asset-set manifest digest.

### Changed

- Split the browser writer into one KZG module and three IPA profile modules.
- Replace the multi-backend writer controller with one immutable
  backend/profile Worker controller and make initialization cancellation and
  idle fatal failures observable.
- Pin the audited `go-ipa` source snapshot inside MALT so verifier and committer
  profiles are built from one reviewable implementation.
- Canonicalize and validate gzip/ustar release archives, provenance, checksums,
  member metadata, padding, and end blocks before publication.

### Compatibility

- These changes do not alter MALT roots, CIDs, transcripts, parameter sets,
  ProofLists, receipts, or proof encodings.
- Browser integrations built against v0.0.7-rc.1 must adopt the split writer
  filenames and `createMaltWriterWorker` controller API.
- Writer asset consumers must validate `malt.web-writer.provenance/v3`; device
  selection and profile retry order remain host policy.
- Unversioned WASM URLs are not immutable release identities. Consumers should
  load one complete digest-addressed asset set and reload when the application
  entrypoint selects a new digest.

## [0.0.7-rc.1] - 2026-07-31

This experimental release candidate centers on three protocol changes:
structured typed-root codecs, backend-sized semantic geometry, and verifiable
Map non-membership.

### Highlights

#### Structured typed roots: `0x30VSBB`

- Define typed MALT root codecs in the private-use `0x30VSBB` layout, where
  `V` is the wire-format version, `S` is the semantic kind, and `BB` is the
  commitment-backend suite.
- New constructors emit `MALTVersionID=3` roots:
  - Map/KZG: `0x303101`
  - List/KZG: `0x303201`
  - Map/IPA: `0x303102`
  - List/IPA: `0x303202`
- Fail closed on unknown versions, semantics, backend suites, combinations,
  identity-hash sizes, and mixed-profile children.
- Retain structured version-2 roots for read, proof, and exact complete-view
  replay compatibility. Default constructors do not emit them.

#### 4096-slot KZG semantic geometry

- Use all 4096 KZG commitment positions in semantic Map and List nodes.
- Consume SHA-256 Map keys as 12-bit radix digits under KZG.
- Reserve List position zero for authenticated metadata and use the remaining
  4095 KZG positions for content.
- Keep IPA at 256 positions, with 8-bit Map radix digits and 255 List content
  positions.
- Share backend-sized geometry between semantic producers, materialization,
  and portable verifiers.

#### Verifiable Map non-membership

- Add root-bound Map membership and non-membership proofs for KZG and IPA.
- Authenticate an absent keyed relation through a proved empty radix slot, a
  conflicting terminal leaf, or a complete fixed-domain collision bucket.
- Add fixed-domain collision buckets under `MALTVersionID=3`, including
  authenticated empty tail positions, so collision-bucket non-membership can
  be verified.
- Add `MapProofRequest`, `MapProofResult`, `MapProver`,
  `VerifyMapProof`, the transport-neutral `malt.map-proof/v0alpha1` profile
  and schemas, and the terminal ProofList step kind `map_absence`.
- Expose the same Map-proof verification boundary through the Go SDK and
  browser/WASM verifier.

### Added

- Add deterministic Resolve/Read conformance corpora; v2 is the current corpus
  for version-3 roots, while v1 is retained as the frozen
  structured-version-2 corpus.
- Add complete-view client-root contracts, `sdk/writer`, exact candidate-root
  bundles, root-bound Map materialization witnesses, and receipt-gated writer
  sessions.
- Add a unified browser writer WASM with isolated KZG and IPA workers.
- Add request-scoped read and writer phase observations for diagnostics.

### Changed

- Align the default Make target and CI build gate with the SDK-only package
  tree.
- Narrow materializer and graph-writer dependencies to the capabilities each
  algorithm consumes.
- Require stable freshness identities where Go value identity cannot safely
  identify a materializer.
- Rebuild a verified structured-version-2 complete view as version 3 before
  applying client-side changes.
- Require exact materialization receipts before a stateful writer session
  advances its retained working view.

### Fixed

- Reject missing authenticated List leaves instead of treating incomplete
  materialization as semantic absence.
- Preserve underlying materializer failures instead of collapsing them into
  not-found results.
- Reject noncanonical Map-proof targets and materialization coordinates.
- Preserve collision-bucket and working-root state across writer preparation,
  receipt recovery, and reachability reclamation.
- Reject target relabeling, invalid UTF-8, stale intents, mismatched receipts,
  and mixed backend/version materialization.

### Removed

- Remove `radix.ProveTimings` and `(*radix.Map).ProveWithTimings`.
- Remove the obsolete process-global `logger` package.
- Remove the former HTTP-oriented `graph/querypath` helper and stale daemon
  configuration example.
- Remove unused `zap` and `multierr` dependencies.

### Compatibility

This is an intentional pre-v1 source- and wire-breaking release candidate.

- v0.0.6 flat root codecs `0x300001` through `0x300004` are not accepted by
  the structured typed-root decoder. No migration layer is provided; recreate
  experimental roots and materialized proof-serving state with this release.
- Structured version-2 roots were introduced on `main` after v0.0.6. They
  remain readable and verifiable, but new constructors emit version 3.
  Collision-bucket non-membership requires the version-3 fixed-domain bucket
  profile.
- Removed Go APIs do not have forwarding compatibility shims.
- Client-root `/v1` suffixes version experimental serialized profiles; they do
  not declare the project or Go APIs stable at v1.
- Client-root bundles and materialization receipts are not portable
  state-transition, publication, freshness, or trust proofs.

## [0.0.6] - 2026-07-14

### Changed

- Recast this module as an SDK-only core: canonical contracts, commitment and
  semantic algorithms, ProofList verification, portable mutation values, and
  untrusted execution composition remain in-tree.
- Move map/list reference implementations to `auth/semantic` and compose graph
  execution under `graph/runtime` over a caller-injected ArcSet materializer.
- Define `auth/arcset/materializer.Store` as an implementation-neutral
  capability; persistent ArcTable/KV implementations now belong to gateways.

### Removed

- CLI/client daemon, HTTP server, CAS/KV backends, concrete ArcTable modes,
  UnixFS, reference executor, and evaluation application packages.
- Core documentation for product HTTP routes and evaluator commands.

These are intentional pre-v1 source breaks. Use `DeWebProtocol/malt-client`
for the trusted CLI/daemon and UnixFS application, and
`DeWebProtocol/gateway` for ArcTable/KV/CAS-backed execution.

## [0.0.5] - 2026-07-13

### Added

- Operation-specific `malt.resolve/v0alpha1` and `malt.read/v0alpha1`
  request, result, verification, JSON Schema, and reference HTTP contracts.
- Portable `mutation` value contracts and a separate untrusted
  `execution.Executor` facade implementing resolve, primitive read, and apply.
- Client-local `sdk/verifier` plus a reproducible browser/WASM verifier build.
- Explicit UnixFS `model/unixfs`, `sdk/unixfs`, and `runtime/unixfs` boundaries.

### Changed

- The module-root `malt` package no longer imports graph writer/execution code;
  it owns query/result/mutation projections and verification bindings only.
- Commitment verification-only interfaces are separated from prover/updater
  capabilities for light-client and WASM consumers.
- The old local daemon bootstrap is identified as a reference executor, and
  remote verify routes are diagnostic/conformance surfaces only.
- `malt verify` performs portable verification locally, binds an explicit
  trusted root and caller-selected canonical query, and exits non-zero on
  rejection.
- The local Go/WASM verifier request binds caller-selected root, operation,
  query, and optional expected target inside the verifier boundary.

### Fixed

- `malt.artifact/v0alpha2` decoders preserve compatibility with v0.0.4
  zero-segment identity queries that omitted `segments`, while canonical output
  emits `segments: []`.
- `malt verify --query ""` accepts a valid zero-step root-identity artifact and
  still binds its root and implied target locally.
- Reference diagnostic verification reuses one lazily initialized portable
  verifier per server and rejects oversized request bodies before initializing
  the KZG/IPA registry.
- UnixFS compatibility helpers return a diagnostic error for a nil CAS reader
  instead of panicking.
- Reference-executor CORS exposes `X-Malt-Verification-Role` so browser clients
  can distinguish diagnostic verification responses.

## [0.0.4] - 2026-07-12

### Added

- Canonical immutable `SegmentPath` values and slash textual projection for
  application-neutral multi-arc resolution.
- Unversioned `artifact` package with the explicit
  `malt.artifact/v0alpha2` resolve/prove/verify contract.
- Embedded JSON Schemas, root-identity conformance fixtures, and stable
  `/v1/artifacts/{resolve,prove,verify}` reference endpoints.
- MIP-1012 and reference specifications for segment-path composition and
  existential resolution.

### Changed

- New integrations carry canonical segment arrays instead of pre-discovering
  how the current graph groups a long path into arcs.
- Reference resolution may prefer the longest prefix, while verification proves
  only the complete returned derivation and makes no longest/unique claim.
- MIP-1004 is finalized with profiled artifacts and machine-readable schemas.

## [0.0.3] - 2026-07-12

### Added

- Module-root `malt` facade with typed `Query`, `ReadRequest`, `ReadResult`,
  `Engine.Read`, `Engine.Apply`, and `Engine.VerifyRead` contracts.
- Portable `auth/verifier` support for runtime-generated KZG and IPA map,
  list-index, and measured-range ProofList evidence without runtime, ArcTable,
  CAS, layout, server, daemon, or network dependencies.
- Separate UnixFS Reader and Writer facades with explicit CAS capabilities.
- MIP-1011 and the experimental `v0alpha1` typed read/result and ProofList
  binding profile.
- Resumable full write-trace replay and expanded read/evaluation workloads.

### Changed

- Generic maps may omit or delete the reserved `@payload` coordinate; UnixFS
  continues to require it as a layout invariant.
- `graph/verifier` is now a thin reference-runtime adapter over the portable
  authentication kernel.
- Graph resolver/writer code consumes narrow ArcTable interfaces, and
  `runtimegraph.NewGraph` no longer accepts an unused CAS argument.
- Upgraded Badger from 4.9.2 to 4.9.4, `go-ipld-format` from 0.6.3
  to 0.6.4, and `golang.org/x/sync` from 0.21.0 to 0.22.0.

### Fixed

- Portable verification now preserves all generic canonical map coordinates
  and maps semantic absence to the public `ErrQueryNotFound` facade error.
- Typed MALT roots reject backend-invalid commitment lengths instead of
  truncating extra digest bytes during verification.
- KZG verification rejects out-of-range proof indices and non-canonical proof
  lengths instead of allowing malformed input to panic or reuse a commitment.

[Unreleased]: https://github.com/DeWebProtocol/malt/compare/v0.0.7-rc.3...HEAD
[0.0.7-rc.3]: https://github.com/DeWebProtocol/malt/compare/v0.0.7-rc.2...v0.0.7-rc.3
[0.0.7-rc.2]: https://github.com/DeWebProtocol/malt/compare/v0.0.7-rc.1...v0.0.7-rc.2
[0.0.7-rc.1]: https://github.com/DeWebProtocol/malt/compare/v0.0.6...v0.0.7-rc.1
[0.0.6]: https://github.com/DeWebProtocol/malt/compare/v0.0.5...v0.0.6
[0.0.5]: https://github.com/DeWebProtocol/malt/compare/v0.0.4...v0.0.5
[0.0.4]: https://github.com/DeWebProtocol/malt/compare/v0.0.3...v0.0.4
[0.0.3]: https://github.com/DeWebProtocol/malt/compare/v0.0.2...v0.0.3

# AGENTS.md

## Scope

This repository is the application-neutral MALT SDK and the technical source
of truth for current protocol, proof, wire-format, CID, compatibility, MIP, and
core conformance behavior. Also follow the workspace guide at `../AGENTS.md`
when this checkout is part of the combined MALT workspace.

## Core Boundary

- Keep canonical values, segment paths, semantic map/list authentication,
  commitments, ProofLists, resolve/read/mutation/client-root contracts, graph
  algorithms, portable verification, and transport-neutral schemas here.
- Core algorithms may consume narrow capabilities under
  `auth/arcset/materializer`, but must not define durable ArcTable, KV, CAS,
  cache, HTTP, daemon, filesystem, UnixFS, Merkle DAG application, tenant,
  publication, or trusted-root policy.
- Treat every resolver, materializer, cache, and gateway as untrusted execution
  state. Verification is relative to a caller-selected root and query.
- Mutation receipts and client-root materialization receipts bind operational
  outcomes; they are not portable transition, publication, freshness, or trust
  proofs and must not be documented as authenticated updates.

## Package Ownership

- The module-root `malt` package owns the minimal in-process semantic facade.
- `auth/` owns ArcSet values, commitments, semantic structures, ProofLists,
  portable proof verification, and optional request-scoped observation hooks.
  Observations are diagnostics, never protocol evidence.
- `graph/` owns application-neutral traversal, runtime composition over injected
  capabilities, and reference writer algorithms.
- `execution/` owns the untrusted resolve/read/apply facade; it does not make
  client trust decisions or own service state.
- `mutation/` owns portable semantic mutation values, complete-view client-root
  values, and operational receipts.
- `protocol/` and `wire/` own versioned transport-neutral JSON/schema and CID
  projections. Incompatible wire changes require a new profile.
- `sdk/writer` owns application-neutral complete-view verification and exact
  client-root computation. It does not own application syntax, durable
  persistence, publication, synchronization, or trusted-root promotion.
- `artifact/` and its verifier entry points are frozen v0.0.4 compatibility
  surfaces. Do not add new operations to `malt.artifact/v0alpha2`.
- `cmd/malt-verifier-wasm` is a portable local-verification build target, not a
  network client or application runtime.

## Cross-Repository Routing

- Put ArcTable/KV/CAS implementations, runtime composition, managed-service
  policy, and product E2E in `gateway/`.
- Put trusted-root policy, CLI/daemon lifecycle, UnixFS behavior, payload-byte
  binding, pluggable transport, and Merkle DAG import in the MALT local runtime
  repository. During the repository migration it remains available as
  `DeWebProtocol/malt-client`; its target repository name is
  `DeWebProtocol/malt`.
- Put executable benchmark runners, adapters, plans, and result schemas in
  `malt-evaluation/`.
- Put public tutorials and product narrative in `web/`, and research/paper
  material in `documents/`.

## Validation And Delivery

- Run `gofmt` on changed Go files, `git diff --check`, `go test ./...`,
  `go vet ./...`, and `go build -buildvcs=false ./...` when practical.
- Keep architecture/import-boundary tests passing whenever packages move.
- Use a topic branch/worktree, commit verified changes, push the branch, and
  open a draft pull request to `main`; do not edit `main` directly unless the
  maintainer explicitly requests it.

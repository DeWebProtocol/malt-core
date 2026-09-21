# AGENTS.md

## Scope

This repository is the application-neutral MALT SDK and the technical source
of truth for current protocol, proof, wire-format, CID, compatibility, MIP, and
core conformance behavior. Also follow the workspace guide at `../AGENTS.md`
when this checkout is part of the combined MALT workspace.

## Core Boundary

- Keep typed inputs, coordinates, Prefix/Positional authentication trees,
  commitments, explicit traversal, authentication query/candidate/batch/receipt
  contracts, portable verification, and transport-neutral schemas here.
- Core algorithms may consume narrow capabilities under
  `auth/arcset/materializer`, but must not define durable ArcTable, KV, CAS,
  cache, HTTP, daemon, filesystem, UnixFS, Merkle DAG application, tenant,
  publication, or trusted-root policy.
- Treat every resolver, materializer, cache, and gateway as untrusted execution
  state. Verification is relative to a caller-selected root and query.
- Authentication materialization receipts bind operational
  outcomes; they are not portable transition, publication, freshness, or trust
  proofs and must not be documented as authenticated updates.

## Pre-beta Refactoring

- MALT has no historical source-compatibility requirement before beta. Migrate
  active callers to the current typed authentication contracts and remove
  superseded APIs, adapters, fallback branches, schemas, fixtures and tests.
- Do not preserve obsolete entry points through forwarding packages, aliases,
  optional-interface detection, or old-version decoding. Historical contracts
  remain available in Git history with their original identifiers.
- Preserve current capabilities when migrating callers, including exact
  candidate materialization and receipt binding. Release pins and deployment
  are separate from source migration; do not silently upgrade either.

## Root Version Policy

Follow [docs/policy/root-versioning.md](docs/policy/root-versioning.md): the
Root format must use `V=0` throughout pre-production; only an explicit
maintainer production-ready/go-live declaration permits `V=1`. Do not
automatically increment this field for experimental format changes or source
releases. Current constructors and readers accept only self-describing `V=0`
Roots. Historical `V=2/3` formats and fixtures retain their original meanings
in Git history; do not relabel them or change CIDv1's container version.

## Package Ownership

- `auth/input` interprets typed inputs; `auth/coordinate` defines coordinates.
- `auth/tree` owns coordinate-only authentication, immutable nodes and updates.
- `auth/engine` binds input rules, layouts and exact profiles to full Roots.
- `auth/commitment` owns independent Committer, Prover, and Verifier capabilities;
  proof generation uses an explicit existing commitment. `auth/observation` owns
  optional diagnostics that never constitute evidence.
- `traversal` composes explicit typed steps across Roots.
- `sdk/authentication` owns local queries, immutable writers, bounded sessions
  and exact candidate batches; its `host` shares native/WASM serialization.
- `sdk/authentication/builtin` optionally installs built-in verification
  profiles. Backend-specific writers inject their own implementation.
- `protocol` and `wire` own current strict JSON schemas and CID/node encoding.
  Incompatible serialized changes require distinct profile identifiers.
- Module-root `malt` is package documentation, not a forwarding facade.
- WASM entrypoints, compilation, browser Workers, distribution archives, and
  native/WASM integration runners belong exclusively to `malt-ts`. Keep the
  portable Go SDK and target-independent conformance corpus here.
- Retired semantic Map/List, resolver, execution/mutation, artifact, old SDK,
  and aggregate Store packages/interfaces must not be restored as adapters.

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

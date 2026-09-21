# Contributing to MALT Core

This repository is the SDK and protocol implementation for MALT graph data
authentication. Keep changes application- and deployment-neutral.

Before a substantial change, read [README](./README.md),
[architecture](./ARCHITECTURE.md), [roadmap](./ROADMAP.md), and the relevant
[MIP](./docs/mips/README.md).

Changes to profiles, ProofList semantics, root codecs, commitment behavior,
segment/arc rules, mutation values, or public Go interfaces must update tests
and documentation in the same PR. Include language-neutral vectors when a
serialized/verifier-facing behavior changes.

## Validation

```bash
git diff --check
go test ./...
go vet ./...
go build -buildvcs=false ./...
```

Run these commands under the workspace resource limits and run `gofmt` before
committing. Prefer behavior-focused and table-driven tests. WASM builds and
browser integration checks belong to `DeWebProtocol/malt-ts`.

## Boundary rules

- Keep module-root `malt`, `protocol`, `mutation`, and verification APIs free of
  transport, storage, process, and application concerns.
- Keep portable verification deterministic and free of materializer/CAS/network
  I/O.
- Use the narrowest injected capability under `auth/arcset/materializer`; do
  not make production algorithms depend on aggregate `Store`, and do not add
  ArcTable/KV persistence formats here.
- Keep HTTP, managed service policy, ArcTable/KV/CAS implementations, and
  product E2E in `DeWebProtocol/gateway`.
- Keep CLI/daemon, accepted-root policy, UnixFS, and application payload
  verification in `DeWebProtocol/malt-client`.
- Keep website/client explanations in `DeWebProtocol/web` and research/paper
  artifacts in `DeWebProtocol/documents`.
- Do not reintroduce removed server, daemon, storage, evaluator, or UnixFS
  packages as forwarding shims.

Pull requests should state what changed, why the boundary is correct, how it
was tested, and any compatibility impact.

# MALT Core

[![Go CI](https://github.com/dewebprotocol/malt-core/actions/workflows/go.yml/badge.svg)](https://github.com/dewebprotocol/malt-core/actions/workflows/go.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

MALT Core authenticates typed relations under a caller-selected Root. Payload
bytes stay in ordinary content-addressed storage. This repository owns the
coordinate-based authentication tree, coordinate derivation, explicit graph
traversal, local verification, and immutable candidate writers.

```text
caller-selected Root + typed query + untrusted result -> local verification
```

Start with [authentication inputs and Roots](docs/spec/authentication-inputs.md),
[query contracts](docs/spec/authentication-contracts.md), and
[writer batches and receipts](docs/spec/authentication-batches.md).
[Architecture](ARCHITECTURE.md), [documentation](docs/README.md), and
[conformance](docs/spec/conformance-corpora.md) describe the implementation.

## Current source API

`auth/tree` implements Prefix and Positional authentication layouts over coordinates.
`derivation.Derive` converts opaque label bytes using Direct or SHA256.
`engine` combines those layers with an exact commitment profile.
`sdk/authentication` constructs, queries, verifies, and updates this state;
`traversal` composes explicit steps across Roots.

`auth/commitment` separates `Committer`, `Prover`, and `Verifier` capabilities.
Proof generation takes an existing commitment. The optional
`sdk/authentication/builtin.NewVerifier` constructor installs built-in verification
profiles; writers inject the capabilities they need. See the
[capability migration](docs/changes/authentication-capabilities.md).

The old Map/List adapters, string resolver, Resolve/Read and Map-proof
contracts, module-root forwarding API, and client-root writer are removed.
There is one typed query profile, `malt.authentication/3`. Complete candidates
use the separate `malt.authentication/2` profile. Root encoding remains
self-describing `V=0` under the [Root version policy](docs/policy/root-versioning.md).

For local verification, construct the request independently of the response:

```go
import (
    "github.com/dewebprotocol/malt-core/sdk/authentication"
    "github.com/dewebprotocol/malt-core/sdk/authentication/builtin"
)

engine, err := builtin.NewVerifier() // built-in KZG and IPA verification profiles
if err != nil {
    return err
}
valid, err := authentication.Verify(engine, request, result)
// Accept this query result only when err == nil && valid.
```

Verification performs no network or storage lookup. Applications hash fetched
payload bytes against the authenticated CID and make their own trust and
freshness decisions. An exact materialization receipt does not promote a Root.

Writers import a complete candidate once with `NewWriter`, apply typed deltas
with `Apply`, and export complete state explicitly with `Export`. Unchanged
immutable nodes are shared without repeated cryptographic validation. This is
retained local state, not a portable state-transition proof.

## Packages and boundaries

| Package | Responsibility |
| --- | --- |
| `auth/coordinate`, `derivation` | Coordinates and deterministic coordinate derivation |
| `auth/tree` | Prefix/Positional construction, updates, binding/range proofs |
| `engine` | Root descriptor, coordinate derivation, exact backend selection |
| `auth/commitment` | KZG and IPA primitives |
| `auth/arcset/materializer` | Narrow injected node lookup/update/snapshot capabilities |
| `traversal` | Explicit traversal across authenticated Roots |
| `sdk/authentication` | Queries, immutable writers, bounded sessions, exact batches |
| `sdk/authentication/host` | Shared native/WASM serialization and session adapter |
| `sdk/authentication/builtin` | Opt-in built-in verification backends |
| `protocol`, `wire/maltcid` | Current strict JSON schemas, node and Root encoding |
| `auth/observation` | Optional diagnostics; never proof evidence |

Gateway owns HTTP, persistence, service policy, and publication. The local MALT
runtime owns UnixFS, trusted roots, payload binding, and CLI/daemon behavior.
`malt-ts` owns WASM entrypoints, builds, conformance runners, release archives,
the supported TypeScript package, and browser lifecycle;
`malt-evaluation` owns reproducible measurement. Core imports none of those
application layers.

## Development and releases

Use the repository's pinned Go toolchain. Run Go validation under the workspace
resource limits in `AGENTS.md`. Browser/WASM validation runs in `malt-ts`:

```bash
go test -p=6 -parallel=6 ./...
go vet -p=6 ./...
go build -p=6 -buildvcs=false ./...
```

This README describes the checked-out source. Use documentation from the exact
tag selected by a consumer; do not combine this API with old published WASM
assets. Source migration, release publication, and downstream adoption are
separate actions. See [compatibility](docs/policy/compatibility.md) and
[release policy](docs/policy/releasing.md).

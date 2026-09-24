# MALT Core

[![Go CI](https://github.com/dewebprotocol/malt-core/actions/workflows/go.yml/badge.svg)](https://github.com/dewebprotocol/malt-core/actions/workflows/go.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**MALT Core is a Go SDK for verifiable data relationships.** Applications use it
to commit labeled links to a Root, generate proofs for queries, and verify the
answers locally against a Root they selected—even when storage and query
execution are untrusted.

For example, an application can authenticate that `report.txt` points to a
particular content CID, prove that a label is missing, or verify a chain of
links through several Roots. Payload bytes stay in the application's
content-addressed storage; Core authenticates the relationships that lead to
them.

## What you can build

- **Verifiable lookups:** prove that a label points to a target CID, or that no
  binding exists for that label.
- **Authenticated graph traversal:** link Roots together and verify each step
  of an explicitly selected traversal.
- **Authenticated sequences and ranges:** prove integer-indexed bindings and
  the segment CIDs covering a byte range in a fixed-chunk sequence.
- **Immutable updates:** create a new Root while retaining the previous state
  and sharing unchanged authentication nodes; export complete candidates for
  materialization elsewhere.
- **Independent local verification:** verify answers with KZG or IPA commitment
  profiles, without contacting a server or reading a storage backend.

Applications choose their trusted Roots, store their data, check fetched bytes
against authenticated CIDs, and decide publication and freshness. Core supplies
authentication; Gateway and the local MALT runtime supply service and application
behavior. Materialization receipts acknowledge execution and are not portable
state-transition proofs.

MALT is **experimental and pre-beta**. Pin an exact release; source and serialized
contracts may change. See the [compatibility policy](docs/policy/compatibility.md).

## Requirements and installation

| Requirement | Details |
| --- | --- |
| Language | Go **1.26.0 or newer**, as declared in [go.mod](go.mod) |
| Operating systems | CI runs the examples on Linux amd64 and cross-compiles them for macOS amd64/arm64 and Windows amd64; macOS/Windows runtime tests are not part of this gate |
| Native dependencies | No C compiler, database, IPFS node, or Gateway is needed to run the examples; CI runs them with `CGO_ENABLED=0` |
| Go dependencies | Downloaded by Go modules from the versions recorded in `go.mod` and `go.sum`; the first build needs access to those modules |

Add Core to an existing Go module:

```bash
go get github.com/dewebprotocol/malt-core@v0.0.10-rc.2
```

Import the packages you need, typically `sdk/authentication`, `engine`,
`maltcid`, and a commitment backend. The module-root package is documentation,
not an SDK facade. Release changes are recorded in the [changelog](CHANGELOG.md).

For JavaScript or TypeScript, use
[malt-ts](https://github.com/DeWebProtocol/malt-ts). It owns the browser API,
Workers, and WASM distribution and binds an exact published Core release.

## Run your first verified query

Clone the source with Git and run the complete binding example:

```bash
git clone https://github.com/DeWebProtocol/malt-core.git
cd malt-core
go run ./examples/binding
```

The [binding example](examples/binding/main.go) creates a label–target binding,
materializes its authentication nodes in memory, and generates a query result.
A separate verification engine then checks that result against the original
request. It also verifies absence and rejects a tampered target.

```text
Binding verified: report.txt
Payload bytes match the authenticated CID
Absence verified: missing.txt
Tampered target rejected
```

All examples are standalone programs with complete imports and error handling.
They use local in-memory data and need no running services. Run them from the
repository root:

| Command | Demonstrates |
| --- | --- |
| `go run ./examples/binding` | Construct, materialize, prove, and independently verify a binding and its absence |
| `go run ./examples/traversal` | Compose two Roots and verify explicit label steps to a content CID |
| `go run ./examples/range` | Encode integer labels, authenticate a byte range, and check and assemble its payload bytes |
| `go run ./examples/update` | Apply an expected-before delta, retain the old Root, and verify both states |

See the [examples guide](examples/README.md) for the API flow and expected output.
These commands use the checked-out source. CI executes every example so they
stay aligned with the SDK.

## Core concepts

An **ArcSet** is a set of application `label → target` bindings. Labels are
opaque bytes; targets are CIDs, which can themselves be MALT Roots. Applications
and Gateway-owned ArcTables retain the submitted label–target bindings for
recovery and future writes.

Authentication derives a coordinate from each label and binds it to the target:

```text
application label --coordinate derivation--> coordinate
coordinate + target --authentication layout + commitment--> Root
```

| Choice | Meaning |
| --- | --- |
| Coordinate derivation | `SHA256` derives a 32-byte coordinate using Core's domain-separated framing; `Direct` parses an already canonical coordinate |
| Authentication layout | `Prefix` organizes 32-byte keys; `Positional` organizes dense integer indices `[0, count)` |
| Commitment profile | An exact KZG or IPA parameter set and encoding, identified in the Root |
| ArcSet organization | The application's choice to group bindings in one Root or compose several Roots; this is not encoded in the Root |

`Direct` accepts exactly 32 key bytes or eight unsigned big-endian index bytes.
Use `coordinate.EncodeKey` or `coordinate.EncodeIndex`; a decimal text label such
as `"42"` is not an encoded index. Prefix accepts Direct or SHA256 derivation;
Positional requires Direct index labels.

The Root identifies the derivation profile, authentication layout, and exact
commitment profile. Coordinate derivation belongs outside `auth`; authentication
trees operate on coordinates. The Root format remains experimental `V=0`,
independently of the SDK version and CIDv1's container version.

Traversal accepts explicit label steps. A slash or `@payload` inside a label has
no built-in meaning. Applications currently assume a single valid resolution
chain; a longest-match search can be an outer lookup strategy, but Core proofs
authenticate the selected chain and do not prove uniqueness or longest-match
selection. See [authentication inputs and Roots](docs/spec/authentication-inputs.md)
and [query contracts](docs/spec/authentication-contracts.md).

## Packages and integration boundaries

| Package | Responsibility |
| --- | --- |
| `sdk/authentication` | Queries, independent verification, immutable writers, bounded sessions, and candidate batches |
| `sdk/authentication/builtin` | Optional verification-only KZG and IPA engines |
| `engine` | Apply Root-selected derivation and combine the tree with commitment capabilities |
| `derivation` | Deterministic conversion of application label bytes to coordinates |
| `auth/coordinate` | Coordinate types and canonical key/index encodings |
| `auth/tree` | Coordinate-only Prefix/Positional construction, updates, and proofs |
| `auth/commitment` | Separate commitment, proving, and verification capabilities; KZG and IPA backends |
| `auth/arcset/materializer` | Narrow injected lookup/update/snapshot capabilities and an in-memory reference implementation |
| `traversal` | Compose explicit authenticated steps across Roots |
| `maltcid` | Root descriptors, exact commitment profile identities, and CID/node encoding |
| `protocol` | Serialized contracts, strict runtime decoding and validation, and JSON schemas |

Core owns no durable ArcTable, KV/CAS backend, HTTP server, or application path
policy. [Gateway](https://github.com/DeWebProtocol/gateway) owns managed services,
persistence, and publication. The [local MALT runtime](https://github.com/DeWebProtocol/malt)
owns UnixFS, trusted roots, payload binding, and CLI/daemon behavior.
[malt-ts](https://github.com/DeWebProtocol/malt-ts) owns browser integration;
[malt-evaluation](https://github.com/DeWebProtocol/malt-evaluation) owns reproducible
measurements.

## Documentation and development

- [Architecture](ARCHITECTURE.md): internal layers, host adapters, and storage capabilities
- [Specifications](docs/spec/README.md): Root encoding, queries, proofs, batches, and receipts
- [Examples](examples/README.md): complete programs using the public Go API
- [Documentation index](docs/README.md): concepts, policies, and implementation history
- [Contributing](CONTRIBUTING.md), [security](SECURITY.md), and [MIT license](LICENSE)

From a source checkout:

```bash
go test -p=6 -parallel=6 ./...
go vet -p=6 ./...
go build -p=6 -buildvcs=false ./...
```

When working in the combined MALT workspace, apply its `AGENTS.md` resource
limits to these commands. Browser/WASM validation runs in `malt-ts`. Use
documentation and assets matching the exact release consumed by your application;
see the [release policy](docs/policy/releasing.md) and
[migration notes](docs/changes/typed-authentication-only.md).

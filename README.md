# MALT Core

[![Go CI](https://github.com/dewebprotocol/malt-core/actions/workflows/go.yml/badge.svg)](https://github.com/dewebprotocol/malt-core/actions/workflows/go.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**MALT Core is a Go SDK for building applications with verifiable data
relationships.** It lets applications check query answers against a data state
they choose to trust, even when another system stores the data or answers the
query.

For example, an application can verify which content an entry refers to,
confirm that an entry is missing, or follow a series of links and check every
step. Verification runs locally in the application.

## What you can do

- **Verify lookups:** confirm what an entry refers to, or that the entry is
  missing.
- **Follow verified relationships:** check each link in a chain of related data.
- **Verify partial reads:** check selected entries and the references needed
  for a requested range.
- **Prepare new versions:** make changes while keeping earlier states available
  for queries and verification.
- **Use your own storage:** add verification to your application without
  adopting a managed storage service.

## Requirements and installation

You need **Go 1.26.0 or newer**. Go downloads the required packages automatically.
The examples run locally without a server or database. They are tested on Linux.
macOS and Windows builds are also checked; see the
[examples guide](examples/README.md#requirements-and-execution) for platform
coverage.

Add MALT Core to an existing Go module:

```bash
go get github.com/dewebprotocol/malt-core@v0.0.10-rc.2
```

For JavaScript or TypeScript, use
[malt-ts](https://github.com/DeWebProtocol/malt-ts).

## Try the examples

Clone the repository and run the first example:

```bash
git clone https://github.com/DeWebProtocol/malt-core.git
cd malt-core
go run ./examples/binding
```

This example verifies a lookup, confirms a missing entry, and rejects an altered
answer. Each example is a complete program you can read, run, and adapt.

Run these commands from the repository root:

| Command | What you will learn |
| --- | --- |
| `go run ./examples/binding` | Verify a lookup and a missing entry |
| `go run ./examples/traversal` | Follow and verify a chain of relationships |
| `go run ./examples/range` | Verify and assemble a partial read |
| `go run ./examples/update` | Update data and verify both the old and new versions |

The [examples guide](examples/README.md) explains each program and shows its
expected output.

## Further reading

- [Architecture](ARCHITECTURE.md) — how MALT Core works
- [Documentation](docs/README.md) — specifications and detailed guides
- [Changelog](CHANGELOG.md) — release changes
- [Contributing](CONTRIBUTING.md) — development and validation instructions
- [Security](SECURITY.md) and [MIT license](LICENSE)

MALT Core is currently experimental. See the
[compatibility policy](docs/policy/compatibility.md) when choosing a release.

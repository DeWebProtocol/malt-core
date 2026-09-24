# MALT Core

[![Go CI](https://github.com/dewebprotocol/malt-core/actions/workflows/go.yml/badge.svg)](https://github.com/dewebprotocol/malt-core/actions/workflows/go.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**MALT turns a collection of structured data into a compact Root.** Given a
Root and a traversal path, a query returns the target together with compact
verification evidence.

A client can use that evidence to verify that the target follows the requested
path from the selected Root, without trusting the system that answered the
query.

## What you can do

- **Generate compact Roots:** represent a collection of structured data with a
  short identifier.
- **Retrieve targets with evidence:** query by Root and traversal path, then
  verify the returned target locally.
- **Check missing entries and partial reads:** confirm absence or verify the
  references needed for a requested range.
- **Prepare new versions:** make changes while keeping earlier states available
  for queries and verification.
- **Use your own storage:** add verification to your application without
  adopting a managed storage service.

## Requirements and installation

This repository provides the Go implementation and SDK for MALT. You need
**Go 1.26.0 or newer**. Go downloads the required packages automatically.
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
go run ./examples/basic
```

Start by committing data to a Root, then producing evidence for a lookup, and
finally verifying the target. The first example demonstrates these three steps
in order. Each example is a complete program you can read, run, and adapt.

Run these commands from the repository root:

| Command | What you will learn |
| --- | --- |
| `go run ./examples/basic` | Commit data, prove a lookup, then verify the target |
| `go run ./examples/traversal` | Follow and verify a chain of relationships |
| `go run ./examples/range` | Verify and assemble a partial read |
| `go run ./examples/query` | Handle a query response, missing entries, and altered answers |
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

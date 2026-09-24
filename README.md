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

## Quick start

The following snippets show **Commit → Prove → Update → Verify** using the same
collection. They are excerpts from the
[complete example](examples/basic/main.go), in execution order.
Its setup creates `e` (a MALT engine) and `state` (two labeled entries pointing
to content CIDs), with `report.txt` as the first entry. Each snippet runs inside
a function returning an error.

### Commit

Commit the collection to a Root. Keep `nodes` available for subsequent queries
and updates:

```go
view, err := e.Interpret(state)
if err != nil {
    return err
}
nodes := memory.NewNodes()
root, err := e.Commit(ctx, view, nodes)
if err != nil {
    return err
}
```

### Prove

Query `report.txt`, a one-step traversal path from the Root. The result contains
both the target and its verification evidence:

```go
label := []byte("report.txt")
result, err := e.Prove(ctx, root, label, nodes)
if err != nil {
    return err
}
```

### Update

Replace that entry with `replacement`, the CID of the revised content.
`Apply` checks the expected previous target and returns a new Root; the original
Root remains available:

```go
updatedRoot, err := e.Apply(ctx, root, []engine.Change{{
    Label: label, Before: state.Entries[0].Target, After: replacement,
}}, nodes, nodes)
if err != nil {
    return err
}
updatedResult, err := e.Prove(ctx, updatedRoot, label, nodes)
if err != nil {
    return err
}
```

Here `Before` comes from the application's original data. `replacement` is
computed from the new content in the complete example.

### Verify

Use a separate verifier to check each result against its selected Root and
query. Verification needs neither the original collection nor `nodes`:

```go
verifier, err := builtin.NewVerifier(maltcid.IPA256)
if err != nil {
    return err
}
valid, err := verifier.Verify(root, label, result)
if err != nil {
    return err
}
if !valid || !result.Present {
    return fmt.Errorf("invalid original binding")
}
updatedValid, err := verifier.Verify(updatedRoot, label, updatedResult)
if err != nil {
    return err
}
if !updatedValid || !updatedResult.Present {
    return fmt.Errorf("invalid updated binding")
}
```

After these checks, `result.Target` and `updatedResult.Target` are verified at
their respective Roots. In this example both Roots are constructed locally;
a client selects its trusted Root and query independently of a query response.

Run the complete program, including imports, setup, and sample data:

```bash
git clone https://github.com/DeWebProtocol/malt-core.git
cd malt-core
go run ./examples/basic
```

See the [examples guide](examples/README.md) for traversal through several
Roots, partial reads, serialized queries, and retained writers.

## Further reading

- [Architecture](ARCHITECTURE.md) — how MALT Core works
- [Documentation](docs/README.md) — specifications and detailed guides
- [Changelog](CHANGELOG.md) — release changes
- [Contributing](CONTRIBUTING.md) — development and validation instructions
- [Security](SECURITY.md) and [MIT license](LICENSE)

MALT Core is currently experimental. See the
[compatibility policy](docs/policy/compatibility.md) when choosing a release.

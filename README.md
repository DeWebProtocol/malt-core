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
- **Build state with objects:** connect Maps, Lists, and custom structs through
  ordinary Go references, then commit the collection from its root object.
- **Retrieve targets with evidence:** query by Root and traversal path, then
  verify the returned target locally.
- **Check missing entries and partial reads:** confirm absence or verify the
  references needed for a requested range.
- **Prepare new versions:** update objects, collect changed relationships and
  new content, and keep earlier states available for queries and verification.
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
go get github.com/dewebprotocol/malt-core@v0.0.10-rc.3
```

The Object API used below is available starting with `v0.0.10-rc.3`.
For JavaScript or TypeScript, use
[malt-ts](https://github.com/DeWebProtocol/malt-ts), which has its own API and
release schedule.

## Quick start

The following snippets show **Commit → Prove → Update → Verify** on one Map.
They are successive excerpts from the [complete example](examples/basic/main.go),
which includes imports, engine initialization (`e`), a context (`ctx`), and the
`materialize` helper for the local query store. Each snippet runs inside a
function returning an error.

### Commit

Put an immutable document in a Map, then commit the Map. Its children are
committed automatically:

```go
collection, err := object.NewMap(e, object.MapConfig(maltcid.IPA256))
if err != nil {
    return err
}
content, err := object.NewImmutable([]byte("A locally verifiable report."))
if err != nil {
    return err
}
if err := collection.Set([]byte("report.txt"), content); err != nil {
    return err
}
root, err := collection.Commit(ctx)
if err != nil {
    return err
}
```

### Prove

Collect the committed data with `Delta(ctx)` and supply it to the example's
in-memory query store. Query `report.txt`, a one-step traversal path, to obtain
the target and its verification evidence:

```go
nodes := memory.NewNodes()
blocks := make(map[string][]byte)
delta, err := collection.Delta(ctx)
if err != nil {
    return err
}
if err := materialize(ctx, e, nodes, blocks, delta); err != nil {
    return err
}
label := []byte("report.txt")
result, err := e.Prove(ctx, root, label, nodes)
if err != nil {
    return err
}
```

The helper retains content bytes in `blocks` and makes the committed
relationships queryable through `nodes`. Your application chooses where to
store this data.

### Update

Replace the document and commit again. `Delta(ctx)` collects changes relative
to the collection's previous successful Commit:

```go
replacement, err := object.NewImmutable([]byte("An updated report."))
if err != nil {
    return err
}
if err := collection.Set(label, replacement); err != nil {
    return err
}
updatedRoot, err := collection.Commit(ctx)
if err != nil {
    return err
}
delta, err = collection.Delta(ctx)
if err != nil {
    return err
}
if err := materialize(ctx, e, nodes, blocks, delta); err != nil {
    return err
}
updatedResult, err := e.Prove(ctx, updatedRoot, label, nodes)
if err != nil {
    return err
}
```

Keep the returned delta until its writes have been handled; the next successful
Commit advances the local comparison baseline. This example retains both
versions in its query store, so the original Root remains queryable.

### Verify

Use a separate verifier to check each result against its selected Root and
query. Verification needs neither the mutable Objects nor the query store:

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
their respective Roots. This example selects Roots it constructed locally;
a client selects its trusted Root and query independently of a query response.
The complete example also checks content bytes against those verified targets.

Run the complete program from this release:

```bash
git clone --branch v0.0.10-rc.3 https://github.com/DeWebProtocol/malt-core.git
cd malt-core
go run ./examples/basic
```

See the [Object guide](docs/guides/objects.md) for Lists, custom structs, and
nested references, and the [examples guide](examples/README.md) for traversal,
partial reads, and serialized queries.

## Further reading

- [Architecture](ARCHITECTURE.md) — how MALT Core works
- [Documentation](docs/README.md) — specifications and detailed guides
- [Changelog](CHANGELOG.md) — release changes
- [Contributing](CONTRIBUTING.md) — development and validation instructions
- [Security](SECURITY.md) and [MIT license](LICENSE)

MALT Core is currently experimental. See the
[compatibility policy](docs/policy/compatibility.md) when choosing a release.

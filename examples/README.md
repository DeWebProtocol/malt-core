# MALT Core examples

Start with **Commit → Prove → Update → Verify** using Objects:

```bash
go run ./examples/basic
```

Each directory contains a complete Go program with imports, configuration,
sample data, and error handling. Run the commands from the repository root.
The [README walkthrough](../README.md#quick-start) shows the basic program's
four steps directly in code.

## 1. Commit, prove, update, and verify with Objects

[Source](basic/main.go). Create an `Immutable` document, put it in a `Map`, and
call the Map's `Commit`. `Delta(ctx)` collects its committed relationships and
content bytes. The example's `materialize` helper retains those bytes in an
application map and imports each ArcSet candidate into a reference in-memory
node store. `engine.Prove` then returns the target and evidence for `report.txt`.

To update the collection, replace its document reference with `Set`, Commit
again, and collect the new delta. A separate verifier checks the original and
updated results against their respective Roots. The program also rejects old
evidence presented against the new Root and checks content bytes against the
verified CIDs.

Expected output:

```text
Commit: collection Root created
Prove: report.txt target and evidence produced
Update: 1 ArcSet and 1 new content block collected
Verify: original and updated targets verified
```

The example selects Roots it constructed locally. A client must select its
trusted Root and query independently of an untrusted executor. Commit and Delta
perform local computation; storage, publication, and root acceptance are
application responsibilities. Save each delta until its writes are handled;
the next successful Commit advances the local comparison baseline.

## 2. Compose Maps, Lists, and custom structs

```bash
go run ./examples/objects
```

[Source](objects/main.go). Construct a Map → tagged Document → List → Immutable
graph with ordinary Go references. Root Commit recursively commits every child.
`root.Delta(ctx)` collects the new ArcSets and content bytes without requiring
the caller to enumerate its Objects. Replacing a List item and committing again
updates the affected ArcSets and collects the new block. The example proves and
independently verifies both versions, including their content CIDs.

Expected output:

```text
Committed object graph, children before parents
Collected 3 ArcSets and 1 content block
Proved traversal to the content CID
Updated 3 ArcSets; collected 1 new content block
Verified both versions; rejected evidence for the wrong Root
```

The [Object guide](../docs/guides/objects.md) covers payloads, struct tags, failed
Commit retries, external CID dependencies and retained snapshots. This example
uses IPA for the Map and Document, and KZG for the List.

## 3. Traverse several Roots with the engine API

```bash
go run ./examples/traversal
```

[Source](traversal/main.go). Construct two ArcSets directly, commit the child
first, and bind its complete Root into the parent:

```text
parent Root --"docs"--> child Root --"report.txt"--> content CID
```

`traversal.ResolvePath` follows explicit label steps and returns the target plus
ordered binding evidence. `traversal.Verify` checks that evidence against the
original Root and steps using a separate verification-only engine. Core does
not split `docs/report.txt` or choose a longest matching label. Both Roots use
the same in-memory node store here.

Expected output:

```text
Commit: child and parent Roots created
Prove: target and traversal evidence produced
Verify: docs -> report.txt -> content CID
Missing second step verified; suffix not evaluated
```

## 4. Prove a byte range

```bash
go run ./examples/range
```

[Source](range/main.go). Commit a Positional sequence, call `ProveRange`, then
call `VerifyRange` against the same Root and byte interval. Only after proof
verification does the application fetch, check, and assemble the payload bytes.

The example splits `hello world` into `hell`, `o wo`, and `rld`, bound at indices
0, 1, and 2 with `ChunkSize=4` and `TotalSize=11`. `coordinate.EncodeIndex`
produces exactly eight unsigned big-endian bytes for each label. Direct
derivation parses those bytes as an index; decimal strings are not index labels.
The requested `[start, end)` offsets are byte positions, distinct from indices.

Expected output:

```text
Commit: sequence Root created
Prove: range evidence produced
Verify: range evidence valid
Direct index labels: 0, 1, 2 (eight-byte big-endian)
Range proof and all segment CIDs verified
Bytes [3,9): lo wor
```

## 5. Use serialized SDK queries

```bash
go run ./examples/query
```

[Source](query/main.go). `authentication.Prepare` builds a complete candidate;
`Materialize` validates and imports its nodes. `authentication.Execute` produces
evidence for a request. After JSON decoding, `authentication.Verify` checks the
response against the client's original request using a separate verifier.
The program also checks payload bytes, proves absence, and rejects tampering.

Expected output:

```text
Binding verified: report.txt
Payload bytes match the authenticated CID
Absence verified: missing.txt
Tampered target rejected
```

## 6. Use retained authentication writers directly

```bash
go run ./examples/update
```

[Source](update/main.go). `BuildWriter` constructs retained state. `Apply`
checks expected previous targets and returns an independent writer for the new
Root, preserving the base. `Export` produces a complete candidate. The program
materializes both versions, then proves and verifies their respective bindings.
`NewWriter` imports an existing complete candidate. These writer operations do
not publish or accept a Root; separately verifying both versions is not a
portable proof of an authorized state transition.

Expected output:

```text
Original Root preserved; updated Root is distinct
Original binding verified
Updated binding verified
```

## Requirements and execution

Use Go 1.26.0 or newer. Go downloads dependencies on the first build. The six
examples need no C compiler, Gateway, database, IPFS node, or external payload
service. CI runs all six with `CGO_ENABLED=0` on Linux amd64 and cross-compiles
them for macOS amd64/arm64 and Windows amd64. Cross-compilation does not claim
runtime coverage on those systems.

The examples select IPA256 with `ipa.ProfileDirect`; the composed Object
example also installs KZG4096. IPA's execution profile controls precomputation,
independently of coordinate derivation. `derivation.SHA256` derives Prefix keys;
`derivation.Direct` accepts canonical key or index bytes.

These commands execute source from this checkout. Objects require
`v0.0.10-rc.3` or later. To use Core in your own module, follow the exact-release
[installation instructions](../README.md#requirements-and-installation).

## Further reading

- [Object construction and change collection](../docs/guides/objects.md)
- [Authentication inputs and Roots](../docs/spec/authentication-inputs.md)
- [Queries and independent verification](../docs/spec/authentication-contracts.md)
- [Candidate batches and receipts](../docs/spec/authentication-batches.md)
- [Architecture and integration boundaries](../ARCHITECTURE.md)

# MALT Core examples

These standalone Go programs demonstrate the public Core API. Start with
[binding](binding/main.go), then explore traversal, ranges, and retained writers.
Each directory contains a complete `main.go`; there is no hidden example helper
package or running service to configure.

## Requirements and execution

Use Go 1.26.0 or newer and run the commands below from the repository root.
Go downloads dependencies on the first build. The examples need no C compiler,
Gateway, database, IPFS node, or external payload service. CI runs all examples with
`CGO_ENABLED=0` on Linux amd64 and cross-compiles them for macOS amd64/arm64 and
Windows amd64. Cross-compilation does not claim runtime coverage on those systems.

The binding, traversal, range and update examples select IPA256 and `ipa.ProfileDirect` to
avoid retaining a fixed-base precomputation table. This execution choice is
independent of **coordinate derivation**: `derivation.SHA256` derives Prefix
keys, while `derivation.Direct` accepts canonical key or index bytes. KZG is
another supported backend; its implementation lives in `auth/commitment/kzg`.
The Object example installs both IPA and KZG to compose a Map with a List.

The commands execute source from this checkout. To use Core in your own Go
module, follow the exact-release [installation instructions](../README.md#requirements-and-installation)
and copy the relevant example's imports and flow.

## 1. Binding, absence, and independent verification

```bash
go run ./examples/binding
```

[Source](binding/main.go). The program:

1. Registers a commitment/proving backend and prepares a Prefix ArcSet with one
   `report.txt → content CID` binding.
2. Selects the locally constructed Root, then materializes authentication nodes
   in a reference in-memory store.
3. Constructs a binding request and obtains an executor's result.
4. Serializes and strictly decodes that result, then uses a separate
   verification-only engine to check it against the original request.
5. Checks payload bytes against the authenticated CID, proves a missing label,
   and demonstrates rejection of a tampered target.

Expected output:

```text
Binding verified: report.txt
Payload bytes match the authenticated CID
Absence verified: missing.txt
Tampered target rejected
```

In an integration, the client must obtain its trusted Root independently of the
untrusted executor. Decoding a result or receiving its declared Root does not
establish trust. `Verify` returns whether evidence is valid; the verified
binding's `Present` field distinguishes presence from absence.

## 2. Explicit traversal through composed Roots

```bash
go run ./examples/traversal
```

[Source](traversal/main.go). Construct the child ArcSet first, then bind its
complete Root into the parent:

```text
parent Root --"docs"--> child Root --"report.txt"--> content CID
```

The client supplies two explicit labels. Core neither splits a path string nor
searches for a longest matching prefix. The example also verifies a missing
second step with an unevaluated suffix.

Expected output:

```text
Traversal verified: docs -> report.txt -> content CID
Missing second step verified; suffix not evaluated
```

Both Roots use one in-memory node lookup in this program. Services can instead
use `ExecuteWithRoots` to supply materialization for each reached Root. This is
application ArcSet organization; no flat/compositional flag is added to a Root.

## 3. Integer labels and authenticated byte ranges

```bash
go run ./examples/range
```

[Source](range/main.go). Split `hello world` into `hell`, `o wo`, and `rld`.
Bind their CIDs at dense indices 0, 1, and 2 in a Positional ArcSet with
`ChunkSize=4` and `TotalSize=11`.

`coordinate.EncodeIndex` produces exactly eight unsigned big-endian bytes for
each label. `derivation.Direct` parses those bytes as the index; it does not
parse decimal strings. The query's `[start, end)` offsets are byte positions,
not binding indices.

After checking the range proof, the client checks each returned segment's bytes
against its authenticated CID and length, then assembles the selected slice.
The in-memory payload map is example application code, separate from Core's
authentication-node materializer.

Expected output:

```text
Direct index labels: 0, 1, 2 (eight-byte big-endian)
Range proof and all segment CIDs verified
Bytes [3,9): lo wor
```

## 4. Immutable updates and complete export

```bash
go run ./examples/update
```

[Source](update/main.go). `BuildWriter` constructs retained local state. `Apply`
checks the expected previous target and returns an independent writer for the
new Root, preserving the base. `Export` explicitly produces each complete
candidate; the program materializes and queries both versions, then verifies
their respective bindings.

Expected output:

```text
Original Root preserved; updated Root is distinct
Original binding verified
Updated binding verified
```

`NewWriter` is the entry point for importing an existing complete candidate;
`BuildWriter` starts from application labels and targets. These local writer
operations do not publish or accept a Root. Verifying both states separately
does not constitute a portable proof of an authorized state transition.

## Further reading

- [Object construction](../docs/guides/objects.md) and [runnable Object example](objects/main.go): recursively Commit, Prove, update a nested child, and Verify; run `go run ./examples/objects`.
- [Authentication inputs and Roots](../docs/spec/authentication-inputs.md)
- [Queries and independent verification](../docs/spec/authentication-contracts.md)
- [Candidate batches and receipts](../docs/spec/authentication-batches.md)
- [Architecture and integration boundaries](../ARCHITECTURE.md)

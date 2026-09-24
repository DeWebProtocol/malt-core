# MALT Core examples

Start with **Commit → Prove → Verify**, using one complete program and the same
Root throughout. From the repository root, with Go 1.26.0 or newer:

```bash
go run ./examples/basic
```

[Complete source](basic/main.go). It commits two labeled entries, proves a
lookup for `report.txt`, and verifies the returned target. The excerpts below
are successive sections of that program; its engine setup and input data are
included in the source. SDK query envelopes, serialization, and retained writers
are introduced in later examples.

## 1. Commit structured data

Describe the collection as an `engine.State` of label–target bindings. In this
example, the targets are content CIDs for two small documents.

`Interpret` derives coordinates from the application labels without creating a
commitment. `Commit` then creates the Root and writes authentication nodes into
a caller-supplied in-memory materializer:

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

Keep the resulting Root and the materialized nodes for the next step. The
prover needs those nodes; the Root alone does not reconstruct the data.
Applications retain their original labels and payload bytes separately.

## 2. Prove a lookup

Choose a label, representing a one-step traversal path from the committed Root:

```go
label := []byte("report.txt")
result, err := e.Prove(ctx, root, label, nodes)
if err != nil {
    return err
}
```

`result.Target` is the returned target; `result.Proof` contains its verification
evidence. `result.Present` distinguishes a present binding from an absence
result. These fields become trustworthy only after verification.

## 3. Verify the result

Create a separate verification-only engine, then check the result against the
original Root and label:

```go
verifier, err := builtin.NewVerifier(maltcid.IPA256)
if err != nil {
    return err
}
valid, err := verifier.Verify(root, label, result)
if err != nil {
    return err
}
if !valid {
    return fmt.Errorf("invalid proof")
}
if !result.Present {
    return fmt.Errorf("expected report.txt to be present")
}
```

Verification needs neither the original collection nor the prover's node
lookup. This example selects the Root it constructed locally. A real client
must select its trusted Root and query independently of the prover's response.
Verifying a binding authenticates a target CID; checking fetched payload bytes
is a separate application step demonstrated by the range and SDK query examples.

Expected output, in Commit/Prove/Verify order:

```text
Commit: Root = bagcifqabaaraeibt34j4shbv7zz32u3thgnsxlujdur6r3kv6qpw3vxjzntaaoqbde
Prove: target = bafkreihxr4h2utl76gyfnxqhmfucmhrzctzxfz4n7jjxohbhag6ip5jtlm; evidence ready
Verify: valid
```

The remaining examples extend this flow. Every directory contains a complete
program with imports, configuration, input data, and error handling.

## 4. Traverse several Roots

```bash
go run ./examples/traversal
```

[Source](traversal/main.go). Apply the same three stages to two composed ArcSets:

1. **Commit:** commit the child, then commit the parent with a link to that
   child's complete Root.
2. **Prove:** `traversal.ResolvePath` follows the caller's explicit steps and
   returns the target plus ordered binding evidence.
3. **Verify:** `traversal.Verify` checks that evidence against the original
   Root and steps using a separate verification-only engine.

```text
parent Root --"docs"--> child Root --"report.txt"--> content CID
```

Both Roots' nodes live in one in-memory materializer here. Core does not split
`docs/report.txt` or select a longest matching label. An additional Prove/Verify
pair demonstrates a missing second step; the suffix is not evaluated.

Expected output:

```text
Commit: child and parent Roots created
Prove: target and traversal evidence produced
Verify: docs -> report.txt -> content CID
Missing second step verified; suffix not evaluated
```

## 5. Prove a byte range

```bash
go run ./examples/range
```

[Source](range/main.go). Commit a Positional sequence, call `ProveRange`, then
call `VerifyRange` against the same Root and byte interval. Only after proof
verification does the application fetch, check, and assemble the payload bytes.

The example splits `hello world` into `hell`, `o wo`, and `rld`, bound at indices
0, 1, and 2 with `ChunkSize=4` and `TotalSize=11`. `coordinate.EncodeIndex` encodes
each label as exactly eight unsigned big-endian bytes; `derivation.Direct`
parses those bytes as an index. Decimal strings are not index labels. The
query's `[start, end)` offsets are byte positions, distinct from binding indices.

The client checks each segment's bytes against its authenticated CID and length,
then assembles the requested slice. The payload map is example application code,
separate from Core's authentication-node materializer.

Expected output:

```text
Commit: sequence Root created
Prove: range evidence produced
Verify: range evidence valid
Direct index labels: 0, 1, 2 (eight-byte big-endian)
Range proof and all segment CIDs verified
Bytes [3,9): lo wor
```

## 6. Use the SDK query contract

```bash
go run ./examples/query
```

[Source](query/main.go). After the direct Commit/Prove/Verify walkthrough, this
example introduces complete candidates and serialized query responses:

- `authentication.Prepare` builds and exports a candidate;
  `Materialize` validates and imports its nodes.
- `authentication.Execute` produces evidence for a request.
- `authentication.Verify` checks the decoded response against the client's
  original request using a separate verification-only engine.

It also checks payload bytes against the authenticated CID, verifies a missing
entry, and rejects a tampered target. A server-supplied request or Root must not
replace the client's selected Root and query.

Expected output:

```text
Binding verified: report.txt
Payload bytes match the authenticated CID
Absence verified: missing.txt
Tampered target rejected
```

## 7. Retain state across updates

```bash
go run ./examples/update
```

[Source](update/main.go). `BuildWriter` commits and retains the initial state.
`Apply` checks the expected previous target and returns an independent writer
for the new Root, preserving the base. `Export` explicitly produces each
complete candidate. The program then proves and verifies the bindings at both
versions through the SDK query contract.

Expected output:

```text
Original Root preserved; updated Root is distinct
Original binding verified
Updated binding verified
```

`NewWriter` imports an existing complete candidate; `BuildWriter` starts from
application labels and targets. These writer operations do not publish or
accept a Root. Verifying both states separately is not a portable proof of an
authorized state transition.

## Requirements and execution

Use Go 1.26.0 or newer. Go downloads dependencies on the first build. The
examples need no C compiler, Gateway, database, IPFS node, or external payload
service. CI runs all five with `CGO_ENABLED=0` on Linux amd64 and cross-compiles
them for macOS amd64/arm64 and Windows amd64. Cross-compilation does not claim
runtime coverage on those systems.

All examples select the IPA256 commitment profile and `ipa.ProfileDirect` to
avoid retaining a fixed-base precomputation table. This execution choice is
independent of coordinate derivation: `derivation.SHA256` derives Prefix keys,
while `derivation.Direct` accepts canonical key or index bytes. KZG is another
supported backend; its implementation lives in `auth/commitment/kzg`.

The commands execute source from this checkout. To use Core in your own Go
module, follow the exact-release [installation instructions](../README.md#requirements-and-installation)
and copy the relevant example's imports and flow.

## Further reading

- [Authentication inputs and Roots](../docs/spec/authentication-inputs.md)
- [Queries and independent verification](../docs/spec/authentication-contracts.md)
- [Candidate batches and receipts](../docs/spec/authentication-batches.md)
- [Architecture and integration boundaries](../ARCHITECTURE.md)

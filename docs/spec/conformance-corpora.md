# Language-Neutral Conformance Corpora

MALT Core publishes checked-in JSON corpora so implementations can test exact
portable behavior without importing the Go reference generator. Corpus profile
identifiers version the test envelopes; they do not replace or revise the wire
profile identifiers carried inside each vector.

## Published corpora

| Corpus | Checked-in data | Purpose |
| --- | --- | --- |
| `malt.resolve-read.conformance/v1` | `conformance/resolve-read/v1/vectors.json` | Frozen structured-version-2 Resolve/Read compatibility |
| `malt.resolve-read.conformance/v2` | `conformance/resolve-read/v2/vectors.json` | Historical version-3 Resolve/Read acceptance and rejection |
| `malt.map-proof.conformance/v1` | `conformance/map-proof/v1/vectors.json` | KZG and IPA Map membership/non-membership verification |
| `malt.client-root.conformance/v1` | `conformance/client-root/v1/vectors.json` | Frozen complete-view V3 candidate-root computation |
| `malt.client-root.conformance/v2` | `conformance/client-root/v2/vectors.json` | V0 candidate-root computation from V0 and historical V3 views |
| `malt.conformance.authentication/0` | `conformance/authentication-v0.json` | Typed V0 Prefix/Positional verification |

Each versioned directory contains `corpus.schema.json`, `vector.schema.json`, and the
frozen `vectors.json`. Consumers must reject unknown corpus or enclosed wire
profiles and should pin the exact corpus digest from the source release or WASM
provenance.

## Map-proof v1

Each vector binds an ID, backend, category, serialized
`malt.map-proof/v0alpha1` verification envelope, and expected boolean outcome.
Both KZG and IPA cover:

- accepted membership and non-membership;
- cryptographic proof tampering;
- cross-root relabeling;
- a caller-selected key mismatch;
- authenticated target tampering; and
- strict JSON rejection of unknown fields.

An implementation passes a vector only when local verification of the exact
serialized request and untrusted result matches `expected.valid`.

## Client-root v1 and v2

Each vector binds a backend, operation identity, complete update view, semantic
intent, and expected outcome. An accepted vector must reproduce the exact
serialized client-root bundle, materialization, next view, and sample receipt.
Rejected vectors cover a stale base, a root-inconsistent complete view, an
unavailable/wrong backend, and strict JSON rejection.

The v1 corpus is immutable and still runs through
`sdk/writer.NewHistoricalRuntime` for exact V3 replay. The v2 corpus runs through
`sdk/writer.NewRuntime`, covering V0-to-V0 writes and V3-to-V0 migration for KZG
and IPA. Its corpus revision `/v2` does not change the Root version: newly
computed Roots remain `V=0` under the [Root version policy](../policy/root-versioning.md).
`LoadClientRoot`, `ClientRootBytes`, and `ClientRootSchema` retain their v1
behavior; select v2 explicitly using their `*Version` counterparts.

The receipt is checked only against the exact computed bundle. Neither the
corpus nor the receipt proves durable persistence, publication, freshness,
trusted-root promotion, or a portable state transition. Those remain caller or
local-runtime policy.

## Reproduction and adapters

The Go generators are deterministic and are invoked by:

```bash
go generate ./conformance
go test ./conformance
```

The browser verifier gate retains the historical Resolve/Read and Map-proof
corpora and also exercises typed V0 authentication. The writer gate checks
backend isolation for native and js/wasm builds, then compares every KZG/IPA
writer artifact against the v2 client-root corpus. It also checks typed V0
preparation and the single-Worker session. Release provenance binds the exact
current corpus digests. Historical client-root output remains an independent
native replay test; it is not the current WASM writer's expected output.
TypeScript, Rust, and other adapters should consume these same JSON
files directly and must not regenerate implementation-specific replacements.

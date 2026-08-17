# Language-Neutral Conformance Corpora

MALT Core publishes checked-in JSON corpora so implementations can test exact
portable behavior without importing the Go reference generator. Corpus profile
identifiers version the test envelopes; they do not replace or revise the wire
profile identifiers carried inside each vector.

## Published corpora

| Corpus | Checked-in data | Purpose |
| --- | --- | --- |
| `malt.resolve-read.conformance/v1` | `conformance/resolve-read/v1/vectors.json` | Frozen structured-version-2 Resolve/Read compatibility |
| `malt.resolve-read.conformance/v2` | `conformance/resolve-read/v2/vectors.json` | Current version-3 Resolve/Read acceptance and rejection |
| `malt.map-proof.conformance/v1` | `conformance/map-proof/v1/vectors.json` | KZG and IPA Map membership/non-membership verification |
| `malt.client-root.conformance/v1` | `conformance/client-root/v1/vectors.json` | Complete-view exact candidate-root computation |

Each directory contains `corpus.schema.json`, `vector.schema.json`, and the
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

## Client-root v1

Each vector binds a backend, operation identity, complete update view, semantic
intent, and expected outcome. An accepted vector must reproduce the exact
serialized client-root bundle, materialization, next view, and sample receipt.
Rejected vectors cover a stale base, a root-inconsistent complete view, an
unavailable/wrong backend, and strict JSON rejection.

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

The checked-in bytes are also exercised by the browser Verifier and Writer
WASM gates. TypeScript, Rust, and other adapters should consume these same JSON
files directly and must not regenerate implementation-specific replacements.

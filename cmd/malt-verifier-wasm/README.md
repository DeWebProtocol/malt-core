# Browser Verifier

Build the deterministic browser verifier bundle from the repository root:

```bash
scripts/build-verifier-wasm.sh dist/verifier
```

After loading the matching Go `wasm_exec.js` and starting the Go runtime, the
module registers:

```text
globalThis.maltVerifyResolve(verificationJSON) -> resultJSON
globalThis.maltVerifyRead(verificationJSON) -> resultJSON
globalThis.maltVerifyMapProof(verificationJSON) -> resultJSON
globalThis.maltVerifyArtifact(requestJSON) -> resultJSON  # v0.0.4 compatibility
```

The default module initializes both built-in commitment backends. IPA verifier
initialization retains only the SRS and barycentric weights; it never creates
the direct/compact/fast committer fixed-base tables. Browser
clients that isolate initialization may set one of the following values before
calling `go.run`:

```js
globalThis.maltVerifierBackend = 'kzg' // KZG-only verifier
globalThis.maltVerifierBackend = 'ipa' // IPA-only verifier
globalThis.maltVerifierBackend = 'all' // default portable verifier
```

Backend selection still comes from each typed MALT root during verification.
A backend-specific instance fails closed when evidence requires a backend that
is not registered. Clients that need cross-backend ProofLists must use the
default `all` instance.

`maltVerifyResolve` accepts one `malt.resolve/v0alpha1` request/result pair;
`maltVerifyRead` accepts one `malt.read/v0alpha1` request/result pair;
`maltVerifyMapProof` accepts one `malt.map-proof/v0alpha1` membership or
non-membership pair. The caller constructs the request from its trusted root and intended query before
passing the untrusted result to WASM. Schemas live in `protocol/schemas/`.

The release gate `scripts/test-verifier-wasm-vectors.sh` runs the current
Resolve/Read v2 corpus together with the frozen
`conformance/map-proof/v1/vectors.json` corpus. It checks the same WASM artifact
with all backends enabled and in backend-selected KZG and IPA runs. The
Map-proof corpus covers membership, non-membership, proof tampering, cross-root
relabeling, wrong-key requests, target tampering, and strict JSON rejection.

For example:

```json
{
  "request": {
    "profile": "malt.resolve/v0alpha1",
    "root": "<client-selected CID>",
    "segments": ["docs", "readme.md", "@payload"]
  },
  "result": {
    "profile": "malt.resolve/v0alpha1",
    "target": "<untrusted returned CID>",
    "prooflist": {}
  }
}
```

The abbreviated ProofList above is not valid evidence. Verification fails
closed unless the request/result profile, root, exact query, target, ordering,
and all cryptographic bindings validate locally. `error` is diagnostic and
`valid` is the acceptance boolean.

`maltVerifyArtifact` remains available solely for the frozen
`malt.artifact/v0alpha2` v0.0.4 compatibility envelope.

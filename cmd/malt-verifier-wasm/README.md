# Browser authentication verifier

Build with `scripts/build-verifier-wasm.sh dist/verifier`. Load the matching
`wasm_exec.js`, instantiate the module, and start the Go runtime. The sole
verification export is:

```text
globalThis.maltVerifyAuthentication(verificationJSON) -> resultJSON
```

It accepts the current `malt.authentication/1` request/result pair. The caller
constructs the Root and typed query independently of the untrusted response.
`valid` is the acceptance boolean; `error` is diagnostic. Verification performs
no network, materializer, or CAS lookup. Applications still bind payload bytes
to authenticated CIDs and select accepted Roots themselves.

Before `go.run`, `globalThis.maltVerifierBackend` may be `all` (default), `kzg`,
or `ipa`. The runtime never overrides a Root's exact VC profile with that host
selection; queries requiring uninstalled profiles fail. Cross-profile traversal
needs every referenced profile installed. IPA verification loads no writer
fixed-base tables.

`scripts/test-verifier-wasm-vectors.sh` checks the current authentication/1
corpus in all three backend selections. Historical Resolve/Read, Map-proof,
and artifact exports are removed. Current loaders require the current ABI.

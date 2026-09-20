# Authentication conformance

The current language-neutral corpus is `conformance/authentication-v1.json`,
with schema `malt.conformance.authentication/1`. Its 20 vectors cover both exact
built-in VC profiles, opaque labels, system payload selectors, literal-label
separation, native keys, explicit traversal absence, measured ranges,
Positional out-of-range evidence, wrong prefixes, and wrong Roots.

Native tests and verifier WASM consume these same checked-in bytes. All-backend
verification accepts valid vectors and rejects hostile vectors. A KZG-only or
IPA-only instance also rejects valid evidence for the uninstalled profile.
Writer WASM checks exact native/WASM Roots, retained branches, hostile inputs,
batch/receipt binding, and single-Worker lifecycle across KZG and all three IPA
execution profiles.

```bash
go run -p=6 ./internal/conformancegen/cmd -out conformance/authentication-v1.json
scripts/test-verifier-wasm-vectors.sh
scripts/test-writer-wasm.sh
```

Run these commands under the workspace's bounded workload scope. Released
corpus bytes and identifiers are immutable. Historical authentication/0,
Resolve/Read, Map-proof, and client-root corpora and loaders are retired from
the current tree and remain in Git history; do not relabel old vectors as
current evidence. A source change with incompatible query semantics requires a
new query profile and corpus identifier.

Release provenance binds the exact current corpus digest. Source-only
integration checks do not update a consumer's published release lock or prove
that distributed assets implement the new API.

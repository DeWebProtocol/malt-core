# Authentication conformance

The current language-neutral corpus is `conformance/authentication-v1.json`,
with schema `malt.conformance.authentication/1`. Its 20 vectors cover both exact
built-in VC profiles, opaque labels, system payload selectors, literal-label
separation, native keys, explicit traversal absence, measured ranges,
Positional out-of-range evidence, wrong prefixes, and wrong Roots.

Core native tests and the malt-ts WASM runners consume these same checked-in
bytes. All-backend
verification accepts valid vectors and rejects hostile vectors. A KZG-only or
IPA-only instance also rejects valid evidence for the uninstalled profile.
Writer WASM checks exact native/WASM Roots, retained branches, hostile inputs,
batch/receipt binding, and single-Worker lifecycle across KZG and all three IPA
execution profiles.

```bash
go run -p=6 ./internal/conformancegen/cmd -out conformance/authentication-v1.json
go test -p=6 -parallel=6 ./conformance
```

Run these commands under the workspace's bounded workload scope. Run `make
test-wasm` in `malt-ts` for the release-locked browser checks, or its explicit
`scripts/test-core-source.sh` for development integration with a Core checkout.
The WASM runners and build adapters live only in that repository. Released
corpus bytes and identifiers are immutable. Historical authentication/0,
Resolve/Read, Map-proof, and client-root corpora and loaders are retired from
the current tree and remain in Git history; do not relabel old vectors as
current evidence. A source change with incompatible query semantics requires a
new query profile and corpus identifier.

The malt-ts WASM release manifest binds the exact Core corpus digest. Source-only
integration checks do not update a consumer's published release lock or prove
that distributed assets implement the new API.

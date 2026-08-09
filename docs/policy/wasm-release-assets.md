# WASM Release Assets

MALT source tags remain the authoritative release artifact. A tagged release
may additionally publish browser-ready verifier and writer bundles as
content-addressed convenience assets.

## Asset-set identity

Verifier and writer files are coordinated sets, not independent binaries. The
asset-set identifier is the lowercase SHA-256 digest of the exact
`SHA256SUMS` bytes for that set. Release archives and served paths include the
full 64-character digest:

```text
malt-verifier-vX.Y.Z-<asset-set-sha256>-<archive-sha256>.tar.gz
malt-writer-vX.Y.Z-<asset-set-sha256>-<archive-sha256>.tar.gz

/verifier/<asset-set-sha256>/malt-verifier.wasm
/writer/<asset-set-sha256>/malt-writer-kzg.wasm
```

The first archive digest names the coordinated extracted asset set; the second
names the exact compressed archive bytes. Either a payload change or an archive
encoding change therefore produces a new release filename.

The verifier set contains its WASM module, the matching `wasm_exec.js`,
`PROVENANCE.json`, and `SHA256SUMS`. The writer set additionally contains all
KZG and IPA profile modules plus its Worker and controller modules. Consumers
must select one complete set and must not mix files from different digests.

A raw-file CID may be recorded as additional provenance, but it does not
replace the asset-set digest. A single WASM CID does not bind the matching Go
runtime, Worker modules, profiles, or provenance.

## HTTP caching

Only a full digest path is immutable. Servers may return
`Cache-Control: public, max-age=31536000, immutable` for those paths because the
bytes at that URL must never be replaced. An unversioned alias must either be
absent or revalidate and redirect to a digest path; it must never be served as
immutable.

The application entrypoint and any "current release" pointer must revalidate.
They select the active asset-set digests. A running client that observes a new
entrypoint must reload before starting another verifier or writer runtime.

## Provenance

Each set binds the exact MALT version and commit, Go version and toolchain,
build target and flags, and file checksums. Writer provenance additionally
binds build tags, IPA committer profiles, IPA parameter identity, retained
table metadata, and Worker fallback policy. Consumers validate these semantic
fields as well as `SHA256SUMS`; a checksum file that was regenerated alongside
tampered metadata is not sufficient provenance.

Build and validate both release bundles from a clean checkout:

```bash
scripts/build-wasm-release.sh vX.Y.Z dist/wasm-release
scripts/check-wasm-release.sh dist/wasm-release
```

The exact Go patch version in `go.mod` is the release toolchain. Archive
timestamps are fixed to the source commit time, archives use normalized ustar
metadata, modes are normalized, module mode is fixed, host target variables are
cleared, and Go code-generation feature variables are fixed. Caller-provided Go
targets, experiments, timestamps, and `umask` therefore cannot change the bytes
published under a release asset name.

The build emits two digest-named archives, one digest-named
`malt.wasm-release/v1` manifest, and a top-level `SHA256SUMS`. Release assets
must not be replaced after publication.

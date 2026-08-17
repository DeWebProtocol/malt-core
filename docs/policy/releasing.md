# Releasing

MALT core uses source tags for experimental releases.

## Validation

Run from the repository root:

Set `MALT_RELEASE_BASE` to the previous authoritative source tag. For
v0.0.7, that tag is `v0.0.7-rc.5`.

```bash
set -euo pipefail
MALT_RELEASE_BASE=v0.0.7-rc.5
git fetch --prune --tags origin
git rev-parse --verify "${MALT_RELEASE_BASE}^{commit}"
git merge-base --is-ancestor "$MALT_RELEASE_BASE" HEAD
git diff --check "${MALT_RELEASE_BASE}...HEAD"
test -z "$(gofmt -l $(find . -name '*.go' -not -path './vendor/*'))"
go test ./...
GOARCH=386 go test ./auth/commitment/kzg ./auth/commitment/ipa
sh scripts/test-verifier-wasm-vectors.sh
scripts/test-writer-wasm.sh
go vet ./...
go build -buildvcs=false ./...
```

Also compile a temporary external Go module against the candidate tag or
commit. It should import only the intended public packages, at minimum:

- module-root `malt`;
- `protocol`;
- `sdk/verifier`;
- `auth/arcset/materializer` when exercising executor composition.

Build and validate the content-addressed browser asset sets using the exact
release version:

```bash
scripts/build-wasm-release.sh vX.Y.Z dist/wasm-release
scripts/check-wasm-release.sh dist/wasm-release
node scripts/test-wasm-release-adversarial.mjs dist/wasm-release
```

The output contract is defined in [WASM Release Assets](./wasm-release-assets.md).
Upload all four emitted files without renaming or replacing them: two
digest-named archives, the digest-named release manifest, and its
`SHA256SUMS`.

Review README, architecture, roadmap, schemas, compatibility policy, threat
model, and release notes. If Web publishes the WASM build, its provenance must
identify the exact MALT commit, Go toolchain, and SHA-256 checksum.

## Tag and release

Tag only the exact validated commit:

```bash
git tag -a vX.Y.Z -m "MALT vX.Y.Z"
git push origin vX.Y.Z
```

The GitHub release must include:

- user-visible and source-breaking changes;
- commit SHA;
- validation commands/results;
- profile/schema compatibility notes;
- known experimental limits.

Source tags are authoritative. WASM bundles are content-addressed convenience
assets with exact provenance; native platform binaries remain build-from-source
until a separate workflow publishes signed artifacts and checksums.

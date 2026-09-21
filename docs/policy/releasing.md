# Releasing

MALT core uses source tags for experimental releases.

The [MALT Root version policy](./root-versioning.md) keeps the refactored
Root's `V=0` throughout pre-production, including experimental source/SDK
releases. Set `V=1` only after the maintainer explicitly declares the system
production ready and going live. This is independent of CIDv1 and package
SemVer; a release workflow must not infer that declaration or bump `V`.
Current constructors and readers use self-describing V0 Roots. Historical
V2/V3 readers and writer-view migration are retired; releases must document
these source and compatibility changes as described in the
[pre-beta API cleanup](../changes/prebeta-cleanup.md).

## Validation

Run from the repository root under the workspace transient CPU scope. Run
resource-intensive workloads sequentially; the flags below also bound compiler
and Go test concurrency:

Set `MALT_RELEASE_BASE` to the previous authoritative source tag. Select it explicitly for the release being prepared.

```bash
set -euo pipefail
MALT_RELEASE_BASE=<previous-source-tag>
git fetch --prune --tags origin
git rev-parse --verify "${MALT_RELEASE_BASE}^{commit}"
git merge-base --is-ancestor "$MALT_RELEASE_BASE" HEAD
git diff --check "${MALT_RELEASE_BASE}...HEAD"
test -z "$(gofmt -l $(rg --files -g '*.go' -g '!vendor/**'))"
go test -p=6 -parallel=6 ./...
GOARCH=386 go test -p=6 -parallel=6 ./auth/commitment/kzg ./auth/commitment/ipa
sh scripts/test-verifier-wasm-vectors.sh
scripts/test-writer-wasm.sh
go vet -p=6 ./...
go build -p=6 -buildvcs=false ./...
```

Also compile a temporary external Go module against the candidate tag or
commit. It should import only the intended public packages, at minimum:

- `sdk/authentication` and `sdk/authentication/builtin`;
- `protocol`, `auth/input`, and `wire/maltcid`;
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

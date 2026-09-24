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
go vet -p=6 ./...
go build -p=6 -buildvcs=false ./...
```

Also compile a temporary external Go module against the candidate tag or
commit. It should import only the intended public packages, at minimum:

- `sdk/authentication` and `sdk/authentication/builtin`;
- `protocol`, `derivation`, and `maltcid`;
- `auth/arcset/materializer` when exercising executor composition.

Review README, architecture, roadmap, schemas, compatibility policy, threat
model, and release notes. Core releases publish the Go module and its protocol
and conformance sources. They do not build or upload WASM assets.

WASM compilation, browser conformance, reproducible archives, Worker lifecycle,
and TypeScript packaging belong to [malt-ts](https://github.com/DeWebProtocol/malt-ts).
That repository adopts an exact published Core tag and commit, verifies Go
module checksums, and builds its own ABI and assets. Its package/release process
is independent of the Core source release.

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

Source tags and their exact Go module checksums identify the Core dependency.
Historical Core WASM releases remain available under their original tags; new
WASM assets are owned and published by malt-ts.

# WASM ownership

MALT Core supplies the portable Go authentication SDK, protocol and encoding
rules, and language-neutral conformance corpus. All WASM entrypoints, ABI glue,
compilation, browser Workers, native/WASM integration runners, reproducible
archives, and supported TypeScript APIs belong to `DeWebProtocol/malt-ts`.

Core no longer contains `cmd/malt-verifier-wasm`, `cmd/malt-writer-wasm`, or
WASM build/release scripts. Its CI runs native Go tests, 32-bit cryptographic
tests, vet, and builds. The existing Go SDK, transport-neutral host adapter,
cryptographic parameter export, and conformance bytes remain unchanged.

Malt-ts owns the migrated runners and compares its WASM results against the
portable corpus from its exact Core dependency. Its source lock binds the
published Core tag, commit, module checksum, and go.mod checksum; Core WASM
manifests and binary assets are no longer prerequisites for adopting a Core
release. Malt-ts independently binds and checks its wrapper inputs, assets,
archive bytes, and release source commit.

Historical Core WASM publications retain their original meaning. This source
migration does not republish Core, change a Root/query profile, or silently
upgrade a consumer's Core dependency.

# Typed authentication is the sole current chain

The pre-beta source migration removes Map/List adapters and their old root
constructors, string resolver and module facade, Resolve/Read and Map-proof
APIs, `execution`, `mutation`, `sdk/writer`, `sdk/verifier`, and the old proof
and semantic packages. Their schemas, conformance loaders/corpora, dedicated
tests, browser exports, and normative API references are removed as well.
Historical revisions retain the original code and contracts.

The current path is input rules -> coordinate-only tree -> typed engine ->
explicit traversal -> authentication SDK. Complete immutable writers and their
bounded host sessions live in `sdk/authentication`; native and WASM entrypoints
share that implementation. There is no aggregate compatibility Store port or
optional old-ABI detection.

Current query profile `malt.authentication/1` authenticates explicit traversal
and early absence. Applications still support flat/hybrid/rooted organization:
flat path bindings may target payload/manifest CIDs directly; rooted content
queries add a typed payload selector at the reached Prefix. Literal labels do
not become system selectors. Positional chunk/range authentication remains.

Ordered candidate batches and exact receipts preserve multi-object writes and
retries without defining a portable transition proof or promoting trusted
Roots. Source callers must adopt these contracts before old entrypoints are
removed. Published dependency locks, release assets, deployment, and trusted-
root acceptance remain separate actions.

The current corpus is authentication/1. Release metadata moves to
`malt.wasm-release/v2`, `malt.web-verifier.provenance/v2`, and
`malt.web-writer.provenance/v4`, binding only the current corpus and ABI. These
source changes do not claim that any new package or release has been published.

# Typed authentication and Map/List VC Trees

Current construction and verification use original labels, checked coordinates
and immutable Map/List VC Trees in `auth/tree`. `engine` binds the Root's
derivation, layout and exact VC profile; `traversal` composes explicit steps.
`sdk/authentication` owns queries, retained writers, sessions and candidates.
The optional Object SDK adds application containers above this chain.

Superseded semantic adapters, string-path resolvers, Resolve/Read, Map-proof,
old SDK facades and aggregate Store interfaces remain in Git history. Current
callers use the [typed query contracts](../spec/authentication-contracts.md) and
[exact candidate/batch/receipt contracts](../spec/authentication-batches.md).
List ranges authenticate element indices; applications own payload conventions,
byte-range translation and payload-byte verification.

Map=1 and List=2 use V=0 with fixed Root/node domains; reconstruct historical
state rather than rewriting CID prefixes. See [compatibility](../policy/compatibility.md)
and [the current portable corpus](../spec/conformance-corpora.md).

Timing adapters belong to Gateway and Evaluation. Core's injected materializer
and VC capabilities carry no metrics or timers. Browser ABI, provenance and WASM
release manifests belong to `malt-ts`; adopting a source change does not publish
a package, change a release lock, deploy a service or promote a trusted Root.

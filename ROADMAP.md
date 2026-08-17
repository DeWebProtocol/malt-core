# MALT Core Roadmap

## v0.0.6 boundary

v0.0.6 turns this repository into an SDK-only core:

- remove CLI, daemon, HTTP server, CAS/KV, ArcTable implementations, UnixFS,
  and evaluation applications;
- retain canonical resolve/read/mutation/ProofList semantics and schemas;
- retain reference map/list/resolver/writer algorithms over an injected ArcSet
  materializer capability;
- keep portable Go/WASM verification independent of execution state;
- move ArcTable/KV/CAS execution to `gateway`;
- move native trusted roots, CLI/daemon, UnixFS, and payload-byte binding to
  `malt-client`; managed browser application behavior lives in
  `gateway/console`.

## v0.0.7 boundary

v0.0.7-rc.1 adds:

- structured typed roots in the private-use `0x30VSBB` codec layout;
- backend-sized semantic geometry, including 4096 KZG positions;
- exact Map membership and non-membership proofs through
  `malt.map-proof/v0alpha1`;
- the experimental complete-view client-root profiles and `sdk/writer` local
  candidate computation;
- unified verifier and writer browser/WASM builds; and
- optional request-scoped phase observations.

The final release freezes dedicated language-neutral Resolve/Read v2,
Map-proof v1, and client-root v1 corpora. Native Go and browser/WASM gates
consume the same checked-in bytes for KZG and IPA. These corpus identifiers are
independent of their enclosed wire-profile identifiers.

## Next core work

1. Add independent TypeScript and Rust adapters that execute the frozen
   language-neutral corpora without changing the corpus bytes.
2. Define verifiable mutation transition semantics before introducing a new
   mutation artifact/profile. Current receipts remain operational only.
3. Harden variable-size measured-list evidence and native multi-open proofs.
4. Stabilize the minimal materializer capability without standardizing any
   ArcTable persistence format.

## Product integration work outside core

- `gateway`: identity/authorization, persistent ArcTable/KV/CAS, root
  publication, cache/quota policy, backend availability, and product E2E.
- `malt-client`: UnixFS CLI/daemon, accepted roots, candidate acceptance,
  local proof verification, and payload-byte validation.
- `gateway/console`: managed browser account/Bucket application and
  client-side UnixFS composition.
- `web`: public explanation, tutorials, and browser-local verification tools.
- future `malt-ts`: TypeScript object syntax and client ergonomics after core
  conformance is stable.

## Not core scope

- a filesystem, object store, or Merkle-DAG replacement API;
- HTTP service routes or managed gateway policy;
- authoritative latest-head or multi-writer policy;
- ArcTable/KV/CAS implementations;
- UnixFS or language-object syntax;
- billing, quota, pinning, GC, abuse control, or deployment secrets.

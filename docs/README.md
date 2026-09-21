# MALT Core documentation

This repository owns current executable authentication semantics, schemas,
proofs, Root encoding, and conformance. Start with the
[specification index](spec/README.md), [architecture](../ARCHITECTURE.md), and
[independent authentication tree](changes/authentication-tree.md).

Current queries use `malt.authentication/1`; complete candidates use the
independent `malt.authentication/0` profile. The
[typed migration](changes/typed-authentication-only.md) records the removal of
superseded APIs. Historical releases and MIPs retain their original meaning.

- [Concepts](concepts/README.md)
- [Compatibility policy](policy/compatibility.md)
- [Threat model](policy/threat-model.md)
- [Root version policy](policy/root-versioning.md)
- [Release process](policy/releasing.md)
- [WASM ownership](changes/wasm-ownership.md)
- [Conformance](spec/conformance-corpora.md)
- [Evaluation ownership](evaluation.md)
- [MIP process and registry](mips/README.md)

Gateway owns managed services, HTTP, persistence, and publication. The local
runtime owns UnixFS, transport, accepted roots, payload binding, and CLI/daemon.
Malt-ts owns the supported TypeScript API and exact release-locked browser
assets. Malt-evaluation owns executable measurements and result provenance;
documents owns cross-repository design context, and malt-paper owns manuscripts.

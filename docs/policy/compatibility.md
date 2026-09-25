# Compatibility policy

MALT is experimental. Before beta, migrate active callers to current contracts
and delete superseded adapters, forwarding APIs, old decoders, schemas,
fixtures, tests, and ABI fallbacks. Current interfaces must not become optional
to accommodate old WASM. Historical contracts remain recoverable in Git with
their original identifiers.

| Current surface | Contract |
| --- | --- |
| Typed queries/results | `malt.authentication/3` |
| Complete candidates | `malt.authentication/2` |
| Retained-state changes | `malt.authentication-delta/1` |
| Ordered candidate submission | `malt.authentication-batch/1` |
| Exact materialization acknowledgement | `malt.authentication-receipt/1` |
| Primitive binding evidence | `malt.binding/0` |
| Root | Self-describing V0, exact layout/derivation profile/VC profile |
| Go SDK | `sdk/authentication` and optional `sdk/object`, experimental source APIs |
| Browser ABI | Complete current typed exports; exact backend/profile required |

The legacy Map/List facade, string-path resolver, Resolve/Read, Map-proof, client-root,
artifact, and aggregate materializer Store interfaces are retired. Root V2/V3
readers and automatic update-view migration are removed. Rebuild experimental
state and dependent parents from current inputs; changing a CID prefix cannot
convert old nodes or proofs. Payload CIDs remain reusable.

The `sdk/object` Map/List constructors added in `v0.0.10-rc.3` build on the
current authentication API. They do not restore the retired facade or introduce
a new wire format. Existing rc.2 consumers need no migration for this addition.

The [Root policy](root-versioning.md) keeps V=0 until an explicit maintainer
production-ready declaration. That field is independent of package versions,
query profiles, schemas, and corpus versions. Incompatible serialized contracts
need distinct profile/schema identifiers; exact VC parameters/encodings need
distinct immutable profile IDs. Unknown profiles and combinations fail closed.

Breaking source changes require updated callers, tests, schemas, and current
documentation. They preserve supported application capabilities, batching,
exact receipt checks, and trust boundaries. Receipts remain operational, never
portable transition or publication proofs.

Pin exact releases. Source integration is distinct from release publication,
downstream Go dependency adoption, and the exact published-Core lock/WASM assets
owned by malt-ts. Do not upgrade locks or deploy as an implicit refactoring step.
Release notes identify the exact commit, changed profiles/APIs, verification,
and remaining limits. Main is an integration branch, not a stable dependency.

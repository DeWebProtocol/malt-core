# Pre-beta Core API cleanup

Current Core constructs and verifies self-describing V0 Roots. Historical
V2/V3 readers and constructors, automatic historical writer-view migration,
and `malt.artifact/v0alpha2` are removed. Recreate old experimental state with
the current implementation; changing CID prefixes does not migrate it.
Existing V0 authentication corpus bytes, VC parameters, and primitive proof
encodings remain unchanged.

## Source migration

| Removed or changed API | Current entry point |
| --- | --- |
| `NewMapForVersion`, `NewListForVersion`, `WithMALTVersion` | `radix.NewMap`, `tree.NewList`, and the current runtime defaults |
| `NewHistoricalRuntime` | `sdk/writer.NewRuntime` with a current V0 update view |
| historical typed-CID constructors and aliases | `maltcid.NewRoot` with an explicit descriptor, or `NewSemanticRoot` for the Map/List convenience API |
| primitive `cid.Cid` parameters/results | `commitment.Value`; use `NewValue`, `ParseValue`, and `CommitmentBytes(profile)` |
| `NodeRef.PrimitiveCID` | `commitment.NewValue(ref.Profile, ref.Commitment)` |
| flat `mapping.Commitment` / `list.Commitment` wrappers | the current semantic adapters or `auth/engine` |
| `NewSetFrom`, `NewSetFromPaths` | error-returning `NewArcSet`, `NewArcSetFromPaths` |
| `graph.Writer`, `CompatWriter`, `ReferenceWriter` and reference arc-update helpers | `graph.MutationWriter`, `StructureCreator`, and caller-owned lookup/snapshot capabilities |
| writer-owned mutation aliases | types and errors in `mutation` |
| `graph/verifier` wrapper | portable `auth/verifier` or `sdk/verifier` |
| artifact package / `sdk/verifier.Request` / `sdk/verifier.Result` / `Verifier.Verify` / `maltVerifyArtifact` | operation-specific resolve/read verification and `protocol.VerificationResult` |

Primitive commitments carry an exact VC profile, without a layout, input rule,
or CID codec. The typed Root layer owns those semantic fields. Engine proof
services use `IndexRootOpener` for prepared openings, then verify each result
against the caller-selected commitment once. Public `IndexRootProver` methods
continue to validate their own outputs. Backend wrappers with preparation
caches should implement `IndexRootOpener` so the engine can use that capability.

Writer construction no longer registers caller materializers in a global map.
Callers own serialization and publication. Retrying a materialization failure
checks its captured base and exact delta; callers must serialize it with other
writes to the same materializer.

## Conformance and downstream adoption

Current corpora are Resolve/Read v3, Map-proof v2, client-root v4, and typed
authentication/0. Historical corpus bytes remain available in Git history under
their original identifiers. See [conformance corpora](../spec/conformance-corpora.md).

Consumers must compile against the selected Core revision when adapting source
APIs. `malt-ts` release assets still require a reviewed lock to an exact
published Core release. A local source integration check is not a package
release or downstream deployment. Historical evaluation baselines retain their
own implementation pins and must not be relabeled as current measurements.

Full candidate export/validation still traverses complete reachable state in
`sdk/authentication.Writer.Update`. Removing duplicate opening verification
does not make that operation proportional only to changed paths.

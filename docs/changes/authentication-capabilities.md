# Authentication capabilities and traversal packages

`traversal` now owns explicit cross-Root proof composition directly at the module
root. `graph/traversal` is removed. Typed steps retain their existing semantics:
a flat path is one label, a nested path supplies each application-selected hop,
and application adapters decide where to split the path. Gateway executes these
queries through `authentication.ExecuteWithRoots` and supplies Root-scoped node
lookups. Core defines no persistent ArcTable or path parsing policy.

The optional built-in verification constructor is
`sdk/authentication/builtin.NewVerifier`. The former
`sdk/authentication/verifier.New` package and constructor are removed. Query
verification remains `authentication.Verify`; immutable writers remain in the
same backend-neutral SDK package.

## Primitive capabilities

`auth/commitment` exposes `Committer`, `Prover`, and `Verifier`, plus the composite
`Backend`. These replace the old combined execution and index interfaces without
aliases. `Committer` computes commitments and checks index-stable replacements.
`Prover.Prove` and `BatchProve` require an existing commitment and return cells
and proof bytes; they never compute a new commitment. Call `Commit` explicitly
when construction is needed. The old combined commit-and-prove signatures and
`ProveAtRoot`/`BatchProveAtRoot` entry points are removed.

`PreparedProver.PrepareOpening(root, cells)` optionally prepares an immutable
`Opening` without recomputing the commitment. Every opened result must be
verified before use or cache admission. The old implicit-commit preparation API
is removed. An evaluator that intentionally measures commitment plus witness
preparation must call both inside its recorded measurement boundary.

`tree.Profile` and the typed engine's shared `Profile` identify exact registered
profiles independently of their execution capabilities. Tree construction needs
only a committer. Proof serving requires proving and verification capabilities;
portable verification needs only verification. A retained Writer can construct
and update owned state with a committer, while importing or checking untrusted
materialization also needs proving and verification. Both built-in verifier
constructors return types with no committing or proving method set.

This is a Go source migration. Root descriptors, canonical node encoding,
commitment and proof bytes, typed query profiles, candidate/batch/receipt
contracts, and browser API semantics retain their existing meaning. Update
source imports and exact dependency pins together. Release tags, browser asset
provenance, and package release locks must identify the release actually used.

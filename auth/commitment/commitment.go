// Package commitment defines independent cryptographic commitment capabilities.
// Backends are restart-safe and do not rely on RAM-only state for correctness.
package commitment

// Committer constructs commitments and performs index-stable replacements.
// It does not require proof generation or verification.
type Committer interface {
	MaxValues() int
	Commit(values []Cell) (Value, error)
	Replace(values []Cell, index uint64, oldValue, newValue Cell) (Value, error)
}

// Prover opens an existing, caller-selected commitment. These methods never
// recompute the commitment and must reject proofs that do not verify against
// root. Batch results follow the supplied ordered index list.
type Prover interface {
	MaxValues() int
	Prove(root Value, values []Cell, index uint64) (value Cell, proof []byte, err error)
	BatchProve(root Value, values []Cell, indices []uint64) (proved []Cell, proof []byte, err error)
}

// Verifier checks supplied evidence without materialization or execution keys.
type Verifier interface {
	MaxValues() int
	VerifyIndex(root Value, index uint64, value Cell, proof []byte) (bool, error)
	BatchVerify(root Value, indices []uint64, values []Cell, proof []byte) (bool, error)
	VerifyProof(root Value, value Cell, proof []byte) (bool, error)
}

// Backend combines all three capabilities for hosts that need all of them.
// Individual algorithms should depend on the narrow capabilities they use.
type Backend interface {
	Committer
	Prover
	Verifier
}

// Opening is prepared auxiliary material for one caller-selected commitment.
// Preparation alone does not authenticate the supplied vector. The consumer
// must verify each Open result before using it or admitting it to a cache.
type Opening interface {
	Root() Value
	Open(index uint64) (value Cell, proof []byte, err error)
}

// PreparedProver optionally reuses auxiliary material across openings without
// computing a commitment. Implementations detach caller buffers and permit
// concurrent Open calls. Cache policy and lifetime belong to the caller.
type PreparedProver interface {
	Prover
	PrepareOpening(root Value, values []Cell) (Opening, error)
}

// SizedOpening reports retained witness bytes, excluding shared immutable
// backend parameters. This is accounting, not serialized evidence.
type SizedOpening interface {
	Opening
	RetainedBytes() uint64
}

// Package commitment defines cryptographic commitment interfaces.
// Primitive backends in this package are restart-safe and do not rely on
// RAM-only state for correctness.
package commitment

// IndexVerifier is the verification-only primitive surface required by light
// clients, browser/WASM builds, and portable ProofList verification.
type IndexVerifier interface {
	// MaxValues returns the maximum number of authenticated values per root.
	MaxValues() int

	// VerifyIndex verifies a proof for one index against the expected cell.
	VerifyIndex(root Value, index uint64, value Cell, proof []byte) (bool, error)

	// BatchVerify verifies a proof payload for an ordered index list against
	// the expected cells in the same order as indices.
	BatchVerify(root Value, indices []uint64, values []Cell, proof []byte) (bool, error)

	// VerifyProof verifies a proof that already carries its own index metadata.
	VerifyProof(root Value, value Cell, proof []byte) (bool, error)
}

// IndexProver is the execution-only primitive surface used to create and
// update commitments and generate proofs.
type IndexProver interface {
	MaxValues() int

	// Commit generates a commitment to a stable indexed cell vector.
	Commit(values []Cell) (Value, error)

	// Prove generates a proof for one index and returns the proved cell.
	Prove(values []Cell, index uint64) (root Value, value Cell, proof []byte, err error)

	// BatchProve generates one proof payload for an ordered index list and
	// returns the proved cells in the same order as indices.
	BatchProve(values []Cell, indices []uint64) (root Value, proved []Cell, proof []byte, err error)

	// Replace performs an index-stable replacement and returns the new root.
	Replace(values []Cell, index uint64, oldValue, newValue Cell) (Value, error)
}

// IndexRootProver generates proofs against a caller-supplied root without
// first recomputing that commitment. Implementations must fail unless the
// generated proof verifies against root. This lets an untrusted proof service
// open client-materialized vectors while keeping commitment computation on the
// client.
type IndexRootProver interface {
	// ProveAtRoot opens one index against root. It must not call Commit.
	ProveAtRoot(root Value, values []Cell, index uint64) (value Cell, proof []byte, err error)

	// BatchProveAtRoot opens an ordered index list against root. It must not
	// call Commit.
	BatchProveAtRoot(root Value, values []Cell, indices []uint64) (proved []Cell, proof []byte, err error)
}

// IndexOpening is an opaque, prepared witness for one committed vector. Root
// returns the computed commitment or the caller-supplied Root, depending on
// the preparation method. A supplied Root is not validated by preparation. Open
// generates an index proof without recomputing that commitment.
type IndexOpening interface {
	Root() Value
	Open(index uint64) (value Cell, proof []byte, err error)
}

// IndexOpener is the optional execution capability for separating commitment
// preparation from proof generation. Preparing an opening computes and binds
// the root once; callers must keep PrepareOpening outside an independently
// measured Open interval.
type IndexOpener interface {
	PrepareOpening(values []Cell) (IndexOpening, error)
}

// IndexCommitment is the full execution backend. Client verification code
// should depend on IndexVerifier instead.
type IndexCommitment interface {
	IndexVerifier
	IndexProver
}

// IndexRootOpener prepares backend auxiliary material without recomputing a
// commitment. Preparation does not authenticate the supplied vector: every
// returned opening must verify against the caller-selected root before use.
// Implementations detach caller buffers and permit concurrent Open calls.
// Cache policy and lifetime belong to the caller, never to the primitive.
type IndexRootOpener interface {
	PrepareOpeningAtRoot(root Value, values []Cell) (IndexOpening, error)
}

// SizedOpening reports estimated retained witness bytes, excluding shared
// immutable backend parameters. This is accounting, not serialized evidence.
type SizedOpening interface {
	IndexOpening
	RetainedBytes() uint64
}

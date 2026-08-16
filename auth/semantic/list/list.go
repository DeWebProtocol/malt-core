// Package list defines the public stable-indexed list semantic for MALT.
//
// This package provides two layers of abstraction:
//   - Commitment: stateless single-step primitives (Commit, ProveSlot, VerifySlot)
//   - Semantics: stateful multi-step operations that combine primitives
//
// The Commitment layer is designed for use by any runtime (gateway, decentralized
// node, light client) without storage dependencies. The Semantics layer combines
// these primitives with storage access for complete operations.
package list

import (
	"context"
	"errors"
	"fmt"

	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/semantic"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

// ErrNotMeasured reports that a plain list does not carry fixed-width byte
// range metadata. Callers may fall back to index semantics for this case.
var ErrNotMeasured = errors.New("list is not measured")

// Iterator iterates over a list view in index order.
type Iterator interface {
	Next() (index uint64, value cid.Cid, ok bool)
	Err() error
}

// View exposes a caller-supplied list snapshot or materialized view.
type View interface {
	Len() uint64
	Get(index uint64) (cid.Cid, bool)
	Iterate() Iterator
}

// Query is the verifiable result for a single list position.
// Length is committed state so that verifiers can distinguish in-range slots
// from out-of-range queries. For a dense stable-indexed list, index < Length
// implies Key is defined; index >= Length implies Key must be cid.Undef.
type Query struct {
	Key    cid.Cid
	Length uint64
}

// RangeMetadata is authenticated measurement metadata for a byte-addressable
// list. ChunkSize is the fixed segment width used to map byte ranges to list
// indexes.
type RangeMetadata struct {
	ChildCount uint64
	TotalSize  uint64
	ChunkSize  uint64
}

// RangeResult is the verifiable result of a byte-range query over a measured
// list. Segments contains the minimal list targets needed to satisfy the
// requested range.
type RangeResult struct {
	Metadata RangeMetadata
	Segments []cid.Cid
}

// Commitment provides stateless single-step commitment primitives for list semantics.
//
// This component handles the cryptographic commitment operations without any
// storage dependencies. It can be used by gateway runtimes, decentralized nodes,
// and light clients alike.
type Commitment struct {
	scheme commitment.IndexCommitment
}

// NewCommitment creates a new list commitment handler.
func NewCommitment(scheme commitment.IndexCommitment) (*Commitment, error) {
	if scheme == nil {
		return nil, fmt.Errorf("index commitment scheme is nil")
	}
	return &Commitment{scheme: scheme}, nil
}

// Scheme returns the underlying commitment scheme.
func (c *Commitment) Scheme() commitment.IndexCommitment {
	return c.scheme
}

// Commit commits a list view to a root using the commitment scheme.
func (c *Commitment) Commit(ctx context.Context, view View) (cid.Cid, error) {
	if view == nil {
		return cid.Undef, fmt.Errorf("view is nil")
	}

	cells := make([]commitment.Cell, view.Len())
	for i := uint64(0); i < view.Len(); i++ {
		value, ok := view.Get(i)
		if !ok {
			return cid.Undef, fmt.Errorf("missing value at index %d", i)
		}
		if !value.Defined() {
			return cid.Undef, fmt.Errorf("value at index %d is undefined", i)
		}
		cells[i] = commitment.CellFromCID(value)
	}

	root, err := c.scheme.Commit(cells)
	if err != nil {
		return cid.Undef, err
	}
	return listTypedRoot(root)
}

// ProveSlot proves one slot in a committed node.
//
// Given the slots of a committed node, this function generates a proof for the
// specified slot index. The caller must ensure that slots correspond to the root.
func (c *Commitment) ProveSlot(root cid.Cid, slots []cid.Cid, slot uint64) (commitment.Cell, []byte, error) {
	if !root.Defined() {
		return nil, nil, fmt.Errorf("root is undefined")
	}

	cells := cellsFromCIDs(slots)
	if rootProver, ok := c.scheme.(commitment.IndexRootProver); ok {
		return rootProver.ProveAtRoot(root, cells, slot)
	}
	provedRoot, value, proof, err := c.scheme.Prove(cells, slot)
	if err != nil {
		return nil, nil, err
	}

	ok, err := maltcid.EqualCommitment(provedRoot, root)
	if err != nil {
		return nil, nil, err
	}
	if !ok {
		return nil, nil, fmt.Errorf("proved root does not match requested root")
	}

	return value, proof, nil
}

// VerifySlot verifies a single slot proof against a committed root.
//
// This function does not require access to the actual slot values - it only
// needs the root commitment, slot index, expected value, and proof bytes.
func (c *Commitment) VerifySlot(root cid.Cid, slot uint64, value commitment.Cell, proof []byte) (bool, error) {
	return c.scheme.VerifyIndex(root, slot, value, proof)
}

// CellsFromCIDs converts a CID slice to commitment cells.
func cellsFromCIDs(values []cid.Cid) []commitment.Cell {
	cells := make([]commitment.Cell, len(values))
	for i, value := range values {
		cells[i] = commitment.CellFromCID(value)
	}
	return cells
}

func listTypedRoot(root cid.Cid) (cid.Cid, error) {
	commBytes, err := maltcid.ExtractCommitment(root)
	if err != nil {
		return cid.Undef, err
	}
	return maltcid.NewTypedCID(maltcid.SemanticKindList, maltcid.BackendKindOf(root), commBytes)
}

// Semantics defines the public stable-indexed list semantics.
//
// This interface combines the single-step commitment primitives with storage
// access to provide complete list operations. Implementations use the
// Commitment primitives internally and add multi-step tree traversal logic.
type Semantics interface {
	// Commitment returns the underlying commitment primitives.
	Commitment() *Commitment

	// Commit commits the supplied list view into the provided graph scope and
	// returns a structure root.
	Commit(ctx context.Context, namespace string, view View) (cid.Cid, error)

	// Prove proves the key (or absence) at index under root.
	Prove(ctx context.Context, namespace string, root cid.Cid, index uint64) (Query, structure.Proof, error)

	// Verify verifies the proof for an index query under root.
	Verify(root cid.Cid, index uint64, expected Query, proof structure.Proof) (bool, error)

	// Replace performs an index-stable replacement at an existing position.
	Replace(ctx context.Context, namespace string, root cid.Cid, index uint64, oldKey, newKey cid.Cid) (cid.Cid, error)

	// Append extends the list by one key and returns the new root and index.
	Append(ctx context.Context, namespace string, root cid.Cid, key cid.Cid) (newRoot cid.Cid, newIndex uint64, err error)

	// Truncate shrinks the committed length while preserving the remaining prefix.
	Truncate(ctx context.Context, namespace string, root cid.Cid, newLen uint64) (cid.Cid, error)
}

// MeasuredSemantics is an optional list extension for byte-addressable list
// layouts. The range proof is composed from authenticated metadata and the
// index proofs for the minimum segment set covering [start, end). A nil end
// means the authenticated total size.
type MeasuredSemantics interface {
	Semantics

	ProveRange(ctx context.Context, namespace string, root cid.Cid, start uint64, end *uint64) (RangeResult, structure.Proof, error)
	VerifyRange(root cid.Cid, start uint64, end *uint64, expected RangeResult, proof structure.Proof) (bool, error)
}

// FixedWidthCommitter is the narrow write-side capability for creating a
// measured list whose entries are fixed-width byte chunks.
type FixedWidthCommitter interface {
	Semantics

	CommitFixed(ctx context.Context, namespace string, chunks []cid.Cid, chunkSize, totalSize uint64) (cid.Cid, error)
}

// FixedWidthAppender is the narrow write-side capability for extending a
// measured list whose entries are fixed-width byte chunks.
type FixedWidthAppender interface {
	Semantics

	AppendFixed(ctx context.Context, namespace string, root cid.Cid, key cid.Cid, totalSize uint64) (newRoot cid.Cid, newIndex uint64, err error)
}

// FixedWidthSemantics combines the fixed-width create and append capabilities.
// Implementations may expose either narrow capability independently.
type FixedWidthSemantics interface {
	FixedWidthCommitter
	FixedWidthAppender
}

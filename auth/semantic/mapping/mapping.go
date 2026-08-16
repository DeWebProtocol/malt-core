// Package mapping defines the public keyed-map semantic for MALT.
//
// This package provides two layers of abstraction:
//   - Commitment: stateless single-step primitives (Commit, ProveSlot, VerifySlot)
//   - Semantics: stateful multi-step operations that combine primitives
//
// The Commitment layer is designed for use by any runtime (gateway, decentralized
// node, light client) without storage dependencies. The Semantics layer combines
// these primitives with storage access for complete operations.
package mapping

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/semantic"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

const bindingPrefix = "malt:map:binding:v1:"

// ErrPathNotFound indicates that a requested map path is absent from the
// committed semantic state. It is retained for read APIs that translate an
// absent verified binding into a not-found error; Prove returns a verifiable
// Binding{Present:false} instead.
var ErrPathNotFound = errors.New("map path not found")

// Iterator iterates over a map view in canonical key order.
type Iterator interface {
	Next() (key arcset.Path, value cid.Cid, ok bool)
	Err() error
}

// View exposes a caller-supplied keyed snapshot or materialized view.
type View interface {
	Len() int
	Get(key arcset.Path) (cid.Cid, bool)
	Iterate() Iterator
}

// Binding is the verifiable result for one keyed binding.
//
// Present=false denotes a cryptographically verifiable non-membership result;
// Value must then be undefined.
type Binding struct {
	Value   cid.Cid
	Present bool
}

// Commitment provides stateless single-step commitment primitives for map semantics.
//
// This component handles the cryptographic commitment operations without any
// storage dependencies. It can be used by gateway runtimes, decentralized nodes,
// and light clients alike.
type Commitment struct {
	scheme commitment.IndexCommitment
}

// NewCommitment creates a new map commitment handler.
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

// Commit commits a map view to a root using keyed binding CID slots.
func (c *Commitment) Commit(ctx context.Context, view View) (cid.Cid, error) {
	if view == nil {
		return cid.Undef, fmt.Errorf("view is nil")
	}

	cells := make([]commitment.Cell, view.Len())
	iter := view.Iterate()
	i := 0
	var previous arcset.Path
	hasPrevious := false
	for {
		key, value, ok := iter.Next()
		if !ok {
			break
		}
		if i >= len(cells) {
			return cid.Undef, fmt.Errorf("view iterator yielded more bindings than Len")
		}
		cell, err := bindingCell(key, value)
		if err != nil {
			return cid.Undef, err
		}
		if hasPrevious && key <= previous {
			return cid.Undef, fmt.Errorf("view iteration is not in canonical key order")
		}
		cells[i] = cell
		previous = key
		hasPrevious = true
		i++
	}
	if err := iter.Err(); err != nil {
		return cid.Undef, err
	}
	if i != len(cells) {
		return cid.Undef, fmt.Errorf("view iterator yielded %d bindings, expected %d", i, len(cells))
	}

	return c.scheme.Commit(cells)
}

// ProveSlot proves one slot in a committed node.
//
// Given the slots of a committed node, this function generates a proof for the
// specified slot index. The caller must ensure that slots correspond to the root.
// For roots produced by Commit, slots are canonical BindingCID values in view
// iteration order rather than bare map target CIDs.
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

// ProveSlots proves an ordered index set in one committed node. The caller
// supplies the complete stable vector, including explicit undefined padding
// when the proof needs to establish canonical tail emptiness.
func (c *Commitment) ProveSlots(root cid.Cid, slots []cid.Cid, indices []uint64) ([]commitment.Cell, []byte, error) {
	if !root.Defined() {
		return nil, nil, fmt.Errorf("root is undefined")
	}
	cells := cellsFromCIDs(slots)
	if rootProver, ok := c.scheme.(commitment.IndexRootProver); ok {
		return rootProver.BatchProveAtRoot(root, cells, indices)
	}
	provedRoot, values, proof, err := c.scheme.BatchProve(cells, indices)
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
	return values, proof, nil
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

// BindingCID encodes one keyed map binding as the CID slot committed by Commit.
func BindingCID(key arcset.Path, value cid.Cid) (cid.Cid, error) {
	if key.IsEmpty() {
		return cid.Undef, fmt.Errorf("key is empty")
	}
	if !value.Defined() {
		return cid.Undef, fmt.Errorf("value is undefined")
	}

	keyBytes := []byte(key.String())
	valueBytes := value.Bytes()
	if len(keyBytes) > 0xffff {
		return cid.Undef, fmt.Errorf("key %q is too long", key.String())
	}

	out := make([]byte, 0, len(bindingPrefix)+2+len(keyBytes)+len(valueBytes))
	out = append(out, []byte(bindingPrefix)...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(keyBytes)))
	out = append(out, keyBytes...)
	out = append(out, valueBytes...)
	sum, err := mh.Sum(out, mh.IDENTITY, len(out))
	if err != nil {
		return cid.Undef, err
	}
	return cid.NewCidV1(cid.Raw, sum), nil
}

func bindingCell(key arcset.Path, value cid.Cid) (commitment.Cell, error) {
	binding, err := BindingCID(key, value)
	if err != nil {
		return nil, err
	}
	return commitment.CellFromCID(binding), nil
}

// BatchUpdate describes one keyed update operation.
type BatchUpdate struct {
	Key      arcset.Path
	OldValue cid.Cid
	NewValue cid.Cid
}

// Semantics defines the public keyed-map semantics.
//
// This interface combines the single-step commitment primitives with storage
// access to provide complete map operations. Implementations use the
// Commitment primitives internally and add multi-step tree traversal logic.
type Semantics interface {
	// Commitment returns the underlying commitment primitives.
	Commitment() *Commitment

	// Commit commits the supplied map view and returns a structure root.
	Commit(ctx context.Context, namespace string, view View) (cid.Cid, error)

	// Prove proves membership or non-membership for key under root. An absent
	// key returns Binding{Present:false} with a root-bound proof; errors denote
	// malformed inputs or unavailable/inconsistent materialization.
	Prove(ctx context.Context, namespace string, root cid.Cid, key arcset.Path) (Binding, structure.Proof, error)

	// Verify verifies the proof for a keyed binding under root.
	Verify(root cid.Cid, key arcset.Path, expected Binding, proof structure.Proof) (bool, error)

	// Update applies insert, replace, or delete semantics over the committed
	// runtime state. oldValue=cid.Undef means insert; newValue=cid.Undef means
	// delete.
	Update(ctx context.Context, namespace string, root cid.Cid, key arcset.Path, oldValue, newValue cid.Cid) (cid.Cid, error)

	// BatchUpdate applies multiple updates atomically. If any update fails,
	// the entire batch is rejected and no state is modified.
	// Updates are applied in an order determined by the implementation to
	// maintain structural consistency.
	BatchUpdate(ctx context.Context, namespace string, root cid.Cid, updates []BatchUpdate) (cid.Cid, error)
}

// MaterializationExporter returns the complete backend-specific proof-serving
// state for a caller-supplied logical map view. The returned ArcSet is
// untrusted transport data until a root-bound validator accepts it against
// the declared root and logical view.
type MaterializationExporter interface {
	ExportMaterialization(context.Context, string, cid.Cid, View) (*arcset.CanonicalArcSet, error)
}

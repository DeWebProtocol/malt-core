// Package mapping defines the public keyed-map semantic for MALT.
// Cryptographic primitives live in auth/commitment; current implementations
// authenticate values through auth/engine.
package mapping

import (
	"context"
	"errors"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	"github.com/dewebprotocol/malt-core/auth/semantic"
	cid "github.com/ipfs/go-cid"
)

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

// BatchUpdate describes one keyed update operation.
type BatchUpdate struct {
	Key      arcset.Path
	OldValue cid.Cid
	NewValue cid.Cid
}

// Semantics defines the public keyed-map semantics.
//
// Implementations combine authentication with caller-owned node materialization.
type Semantics interface {
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

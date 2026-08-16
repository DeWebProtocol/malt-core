// Package materializer defines the minimal untrusted ArcSet loading and
// materialization capabilities consumed by MALT execution algorithms.
//
// The interfaces deliberately say nothing about persistence, indexing,
// transactions, namespaces on disk, or an ArcTable implementation. A gateway
// may satisfy them with memory, a KV-backed ArcTable, SQL, object storage, or a
// remote service. Portable verification does not depend on this package.
package materializer

import (
	"context"
	"errors"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	cid "github.com/ipfs/go-cid"
)

// ErrNotFound reports that a requested coordinate is absent from the supplied
// ArcSet materialization.
var ErrNotFound = arcset.ErrNotFound

// ErrIncomplete reports that physical materialization for an authenticated
// object is absent, incomplete, or inconsistent with the object named by its
// root. It is distinct from backend I/O failures so callers can classify
// unavailable object state without hiding retryable storage errors.
var ErrIncomplete = errors.New("materialized state is incomplete")

// IsNotFound reports whether err represents an absent materialized arc.
func IsNotFound(err error) bool {
	return errors.Is(err, ErrNotFound)
}

// IsIncomplete reports whether err represents incomplete physical state for
// an authenticated object.
func IsIncomplete(err error) bool {
	return errors.Is(err, ErrIncomplete)
}

// Lookup is the read-only coordinate lookup capability used by semantic
// provers. Scope is opaque execution context chosen by the caller; MALT does
// not assign tenant, graph, bucket, or persistence meaning to it.
type Lookup interface {
	Get(context.Context, string, cid.Cid, arcset.Path) (cid.Cid, error)
	BatchGet(context.Context, string, cid.Cid, []arcset.Path) (map[arcset.Path]cid.Cid, error)
}

// Updater materializes an immutable ArcSet root relative to an optional
// previous root. Transaction and persistence semantics remain caller-owned.
type Updater interface {
	// Update materializes a new immutable ArcSet root relative to an optional
	// previous root. Transaction and persistence semantics remain caller-owned.
	Update(context.Context, string, cid.Cid, cid.Cid, arcset.ArcSet) error
}

// Snapshotter opens a complete root-relative ArcSet view.
type Snapshotter interface {
	Snapshot(context.Context, string, cid.Cid) (arcset.ArcSet, error)
}

// Iterator opens a streaming root-relative ArcSet traversal.
type Iterator interface {
	Iterate(context.Context, string, cid.Cid) arcset.Iterator
}

// NodeStore is the minimal mutable capability used by the reference map/list
// commitment implementations for internal node slots.
type NodeStore interface {
	Lookup
	Updater
}

// RootedNodeUpdater optionally records which semantic node root owns an
// unversioned node-cache ArcSet. Reference semantic implementations use it
// when available so bounded in-memory sessions can reclaim unreachable node
// caches without changing the portable Lookup/Updater contract.
type RootedNodeUpdater interface {
	UpdateNode(context.Context, string, cid.Cid, arcset.ArcSet) error
}

// MutableStore is the capability required by graph mutation/reference writer
// algorithms. It deliberately does not require iteration.
type MutableStore interface {
	NodeStore
	Snapshotter
}

// Store is the full compatibility aggregate implemented by the in-memory
// conformance store and current Gateway ArcTable adapters. New algorithms
// should accept the narrowest capability above instead of Store.
type Store interface {
	MutableStore
	Iterator
}

// BranchingStore is an optional capability for materializers that preserve
// concurrent children of the same parent root.
type BranchingStore interface {
	SupportsConcurrentBranches() bool
}

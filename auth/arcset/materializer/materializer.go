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

// NodeStore combines CID-valued lookup and update capabilities for encoded
// internal node slots.
type NodeStore interface {
	Lookup
	Updater
}

// RootedNodeUpdater records which internal node identity owns an unversioned
// node ArcSet. Encoded adapters expose it to caller-owned storage for ownership
// checks and accounting; SDK sessions manage retained tree state independently.
type RootedNodeUpdater interface {
	UpdateNode(context.Context, string, cid.Cid, arcset.ArcSet) error
}

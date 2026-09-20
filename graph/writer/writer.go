// Package writer implements semantic mutations over caller-owned ArcSet materialization.
package writer

import (
	"context"
	"fmt"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	materialization "github.com/dewebprotocol/malt-core/auth/arcset/materializer"
	"github.com/dewebprotocol/malt-core/auth/semantic/list"
	"github.com/dewebprotocol/malt-core/auth/semantic/mapping"
	cid "github.com/ipfs/go-cid"
)

// Materializer is the caller-injected ArcSet capability consumed by Writer.
// It is an alias for the core materializer contract, not a persistence model.
type Materializer = materialization.MutableStore

// BranchingMaterializer optionally reports support for concurrent children.
type BranchingMaterializer = materialization.BranchingStore

var ErrEmptyPath = arcset.ErrEmptyPath

// Writer executes semantic mutations over caller-owned materialization.
// Callers own serialization, candidate roots, and publication. Product code
// consumes the narrow graph.MutationWriter or graph.StructureCreator interface.
type Writer struct {
	semantic     mapping.Semantics
	listSemantic list.Semantics
	materializer Materializer
}

// NewWriter creates a new Writer.
//
// Parameters:
//   - semantic: keyed-map semantic (required)
//   - materializer: caller-owned ArcSet materialization (required)
func NewWriter(semantic mapping.Semantics, materializer Materializer, lists ...list.Semantics) *Writer {
	var listSemantic list.Semantics
	if len(lists) > 0 {
		listSemantic = lists[0]
	}
	return &Writer{
		semantic:     semantic,
		listSemantic: listSemantic,
		materializer: materializer,
	}
}

func canonicalizeSnapshot(arcs arcset.ArcSet) (arcset.ArcSet, map[arcset.Path]cid.Cid, error) {
	if arcs == nil {
		return nil, nil, fmt.Errorf("arc set is nil")
	}

	arcsMap := make(map[arcset.Path]cid.Cid, arcs.Len())
	iter := arcs.Iterate()
	for {
		path, target, ok := iter.Next()
		if !ok {
			break
		}
		if path.IsEmpty() {
			return nil, nil, ErrEmptyPath
		}
		if !target.Defined() {
			continue
		}
		if existing, ok := arcsMap[path]; ok && !existing.Equals(target) {
			return nil, nil, fmt.Errorf("duplicate canonical path %q in arc set", path.String())
		}
		arcsMap[path] = target
	}
	if iter.Err() != nil {
		return nil, nil, fmt.Errorf("arc iteration error: %w", iter.Err())
	}

	normalized, err := arcset.NewArcSetFromPaths(arcsMap)
	if err != nil {
		return nil, nil, err
	}
	return normalized, arcsMap, nil
}

// CreateStructure creates a new structure from an arc set.
//
// This is the initial commitment operation:
//  1. Commits the arc set via the semantic layer
//  2. Stores arcs in Materializer (first version, no parent)
func (w *Writer) CreateStructure(ctx context.Context, namespace string, arcs arcset.ArcSet) (cid.Cid, error) {
	if arcs == nil {
		return cid.Undef, fmt.Errorf("arc set is nil")
	}
	normalizedSnapshot, _, err := canonicalizeSnapshot(arcs)
	if err != nil {
		return cid.Undef, err
	}
	// Step 1: Commit arc set via semantic layer
	view, err := mapping.NewViewFromArcSet(normalizedSnapshot)
	if err != nil {
		return cid.Undef, err
	}
	root, err := w.semantic.Commit(ctx, namespace, view)
	if err != nil {
		return cid.Undef, fmt.Errorf("semantic.Commit failed: %w", err)
	}
	retryBase, err := materializationRetryBase(ctx, w.materializer, namespace)
	if err != nil {
		return cid.Undef, &MaterializationWriteFailedError{
			NewRoot:              root,
			Namespace:            namespace,
			OldRoot:              cid.Undef,
			MaterializationDelta: normalizedSnapshot,
			Cause:                fmt.Errorf("Materializer.Snapshot retry base failed: %w", err),
		}
	}

	// Step 2: Store arcs in Materializer (first version). On failure root is
	// semantically committed but has no index entries; surface it for retry.
	if err := w.materializer.Update(ctx, namespace, root, cid.Undef, normalizedSnapshot); err != nil {
		return cid.Undef, &MaterializationWriteFailedError{
			NewRoot:              root,
			Namespace:            namespace,
			OldRoot:              cid.Undef,
			MaterializationBase:  retryBase,
			MaterializationDelta: normalizedSnapshot,
			Cause:                fmt.Errorf("Materializer.Update failed: %w", err),
		}
	}

	return root, nil
}

// RetryMaterializationWrite retries an exact failed transition. The caller owns
// serialization and publication; no process-global state is retained by Core.
func (w *Writer) RetryMaterializationWrite(ctx context.Context, failure *MaterializationWriteFailedError) error {
	if w == nil {
		return fmt.Errorf("writer is nil")
	}
	return failure.retryMaterializationWrite(ctx, w.materializer)
}

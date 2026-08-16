// Package writer implements semantic mutation and explicitly reference-only
// arc update algorithms over caller-owned ArcSet materialization.
package writer

import (
	"context"
	"errors"
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

// FreshnessIdentityProvider gives legacy root-consuming writer helpers a stable
// process-local identity for one non-branching Materializer backend. Wrappers
// that are not comparable, or multiple wrapper instances over the same
// backend, must return the same non-empty identity so Writers share one guard.
type FreshnessIdentityProvider interface {
	FreshnessIdentity() string
}

var (
	// ErrArcNotFound is returned when the target arc does not exist for a replace/delete operation.
	ErrArcNotFound = errors.New("arc not found")

	// ErrInvalidRoot is returned when the structure root is undefined.
	ErrInvalidRoot = errors.New("invalid structure root")

	// ErrEmptyPath is returned when the path is empty.
	ErrEmptyPath = arcset.ErrEmptyPath

	// ErrStaleRoot is returned when a legacy root-consuming write attempts to
	// update a base root that this writer has already advanced in the same
	// namespace.
	ErrStaleRoot = errors.New("stale root")

	// ErrFreshnessIdentityUnavailable reports that a non-branching Materializer
	// cannot safely share legacy root-consumption state across Writer instances.
	ErrFreshnessIdentityUnavailable = errors.New("materializer freshness identity is unavailable")
)

// ArcOp describes the type of arc operation performed.
type ArcOp uint8

const (
	// ArcInsert creates a new arc (⊥ → c).
	ArcInsert ArcOp = iota
	// ArcReplace updates an existing arc (c → c').
	ArcReplace
	// ArcDelete removes an arc (c → ⊥).
	ArcDelete
)

func (op ArcOp) String() string {
	switch op {
	case ArcInsert:
		return "insert"
	case ArcReplace:
		return "replace"
	case ArcDelete:
		return "delete"
	default:
		return "unknown"
	}
}

// UpdateResult records the outcome of a single arc update.
type UpdateResult struct {
	// OldRoot is the structure root before the update.
	OldRoot cid.Cid

	// NewRoot is the structure root after the update.
	NewRoot cid.Cid

	// Path is the arc path that was updated.
	Path arcset.Path

	// OldTarget is the previous target CID (cid.Undef if insert).
	OldTarget cid.Cid

	// NewTarget is the new target CID (cid.Undef if delete).
	NewTarget cid.Cid

	// Op is the operation type.
	Op ArcOp
}

// BatchUpdateResult records the outcome of a batch arc update.
type BatchUpdateResult struct {
	// OldRoot is the structure root before the update.
	OldRoot cid.Cid

	// NewRoot is the structure root after the update.
	NewRoot cid.Cid

	// PerArc contains the result for each updated arc.
	PerArc map[arcset.Path]UpdateResult
}

// Writer implements semantic mutation plus the legacy reference helpers exposed
// through graph.ReferenceWriter. Product callers should receive it through a
// narrow graph.MutationWriter or graph.StructureCreator interface.
//
// The legacy UpdateArc/BatchUpdateArcs paths only enforce single-consumer root
// freshness for non-branching Materializer backends. MVCC-style backends such as
// versioned Materializer remain branchable and may accept multiple children from
// the same parent root.
//
// Symmetric to Resolver on the read side:
//   - Resolver: (root, path) -> (target, transcript) via Materializer lookup + semantic prove
//   - Writer:   (root, path, newTarget) -> newRoot via semantic update + Materializer apply
type Writer struct {
	semantic     mapping.Semantics
	listSemantic list.Semantics
	materializer Materializer
	freshness    *rootFreshnessGuard
	freshnessErr error
}

// NewWriter creates a new Writer.
//
// Parameters:
//   - semantic: keyed-map semantic (required)
//   - materializer: Explicit Arc Table (required)
func NewWriter(semantic mapping.Semantics, materializer Materializer, lists ...list.Semantics) *Writer {
	var listSemantic list.Semantics
	if len(lists) > 0 {
		listSemantic = lists[0]
	}
	freshness, freshnessErr := rootFreshnessGuardFor(materializer)
	return &Writer{
		semantic:     semantic,
		listSemantic: listSemantic,
		materializer: materializer,
		freshness:    freshness,
		freshnessErr: freshnessErr,
	}
}

// RetryMaterializationWrite retries a failed writer-level Materializer publication.
//
// The retry is serialized through the same freshness guard as UpdateArc and
// BatchUpdateArcs for non-branching Materializer backends. This closes the window
// where a captured failed retry could race with a later root-consuming write for
// the same (namespace, oldRoot) and overwrite namespace-scoped arc entries.
func (w *Writer) RetryMaterializationWrite(ctx context.Context, err *MaterializationWriteFailedError) error {
	if w == nil {
		return fmt.Errorf("writer is nil")
	}
	if err == nil {
		return fmt.Errorf("materialization write failure is nil")
	}
	if err.OldRoot.Defined() && w.freshnessErr != nil {
		return w.freshnessErr
	}
	if w.freshness != nil && err.OldRoot.Defined() {
		unlock, beginErr := w.freshness.beginUpdate(err.Namespace, err.OldRoot)
		if beginErr != nil {
			return beginErr
		}
		defer unlock()
	}
	if retryErr := err.retryMaterializationWrite(ctx, w.materializer); retryErr != nil {
		return retryErr
	}
	if w.freshness != nil {
		if err.OldRoot.Defined() {
			w.freshness.markAdvancedLocked(err.Namespace, err.OldRoot, err.NewRoot)
		} else {
			w.freshness.markCurrent(err.Namespace, err.NewRoot)
		}
	}
	return nil
}

func canonicalizeUpdateMap(updates map[string]cid.Cid) (map[arcset.Path]cid.Cid, error) {
	snapshot, err := arcset.NewArcSet(updates)
	if err != nil {
		return nil, err
	}
	return arcset.ToPathMap(snapshot)
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

func diffArcMaps(oldArcs, newArcs map[arcset.Path]cid.Cid) (arcset.ArcSet, error) {
	diff := make(map[arcset.Path]cid.Cid)

	for path, newTarget := range newArcs {
		oldTarget, ok := oldArcs[path]
		if !ok || !oldTarget.Equals(newTarget) {
			diff[path] = newTarget
		}
	}

	for path := range oldArcs {
		if _, ok := newArcs[path]; !ok {
			diff[path] = cid.Undef
		}
	}

	return arcset.NewArcSetFromPaths(diff)
}

func filterLogicalArcSet(arcs arcset.ArcSet) (arcset.ArcSet, error) {
	if arcs == nil {
		return nil, nil
	}

	out := make(map[arcset.Path]cid.Cid)
	iter := arcs.Iterate()
	for {
		path, target, ok := iter.Next()
		if !ok {
			break
		}
		if path.HasPrefix(arcset.CanonicalizePath("runtime")) {
			continue
		}
		out[path] = target
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("arc iteration error: %w", err)
	}
	filtered, err := arcset.NewArcSetFromPaths(out)
	if err != nil {
		return nil, err
	}
	return filtered, nil
}

// UpdateArc executes the unified arc update procedure.
//
// Given a structure root, path, and new target CID, this method:
//  1. Looks up the current binding: c = Materializer.Get(root, path)
//  2. Updates the commitment: newRoot = semantic.Update(root, path, c, newTarget)
//  3. Applies the update to Materializer using the full new arc set for newRoot
//
// UpdateArc is a legacy root-consuming API. Within one process, writers that
// share the same Materializer instance advance (namespace, root) exactly once for
// successful non-no-op calls; later attempts to update the same base root return
// ErrStaleRoot instead of silently forking or overwriting Materializer state.
//
// The operation covers three semantic cases:
//   - Insert (⊥ → c)
//   - Replace (c -> c')
//   - Delete (c → ⊥)
func (w *Writer) UpdateArc(ctx context.Context, namespace string, root cid.Cid, path string, newTarget cid.Cid) (*UpdateResult, error) {
	if !root.Defined() {
		return nil, ErrInvalidRoot
	}
	canonicalPath := arcset.CanonicalizePath(path)
	if canonicalPath.IsEmpty() {
		return nil, ErrEmptyPath
	}
	if w.freshnessErr != nil {
		return nil, w.freshnessErr
	}
	if w.freshness != nil {
		unlock, err := w.freshness.beginUpdate(namespace, root)
		if err != nil {
			return nil, err
		}
		defer unlock()
	}

	// Step 1: Snapshot the current arc set for delta computation, then read the
	// target path through Materializer.Get for operation
	// classification. Get must stay in the classification path because some
	// backends may tolerate corrupt entries while materializing broad snapshots;
	// a targeted read needs to fail closed instead of turning corruption into a
	// missing-arc no-op.
	snapshot, err := w.materializer.Snapshot(ctx, namespace, root)
	if err != nil {
		return nil, fmt.Errorf("Materializer.Snapshot failed: %w", err)
	}
	oldTarget, err := w.materializer.Get(ctx, namespace, root, canonicalPath)
	if err != nil {
		if !errors.Is(err, arcset.ErrNotFound) {
			return nil, fmt.Errorf("Materializer.Get failed: %w", err)
		}
		oldTarget = cid.Undef
	}

	// Determine operation type
	var op ArcOp
	isInsert := !oldTarget.Defined() && newTarget.Defined()
	isReplace := oldTarget.Defined() && newTarget.Defined()
	isDelete := oldTarget.Defined() && !newTarget.Defined()

	if isInsert {
		op = ArcInsert
	} else if isReplace {
		op = ArcReplace
	} else if isDelete {
		op = ArcDelete
	} else {
		// Both undefined: no-op
		return &UpdateResult{
			OldRoot:   root,
			NewRoot:   root,
			Path:      canonicalPath,
			OldTarget: oldTarget,
			NewTarget: newTarget,
			Op:        ArcInsert,
		}, nil
	}

	var newRoot cid.Cid
	newRoot, err = w.semantic.Update(ctx, namespace, root, canonicalPath, oldTarget, newTarget)
	if err != nil {
		return nil, fmt.Errorf("semantic.Update failed for arc %s: %w", op, err)
	}

	oldArcs, err := arcset.ToPathMap(snapshot)
	if err != nil {
		return nil, err
	}
	updatedArcs := make(map[arcset.Path]cid.Cid, len(oldArcs)+1)
	for path, target := range oldArcs {
		updatedArcs[path] = target
	}
	if newTarget.Defined() {
		updatedArcs[canonicalPath] = newTarget
	} else {
		delete(updatedArcs, canonicalPath)
	}
	delta, err := diffArcMaps(oldArcs, updatedArcs)
	if err != nil {
		return nil, err
	}
	retryBase, err := materializationRetryBase(ctx, w.materializer, namespace)
	if err != nil {
		return nil, &MaterializationWriteFailedError{
			NewRoot:              newRoot,
			Namespace:            namespace,
			OldRoot:              root,
			MaterializationDelta: delta,
			Cause:                fmt.Errorf("Materializer.Snapshot retry base failed: %w", err),
		}
	}

	// Step 3: Apply update to Materializer as an old->new delta. This keeps versioned Materializer
	// compact while still emitting tombstones for deletions. If this fails the
	// newRoot is semantically valid but unreadable via the index; surface it so
	// the caller can retry the idempotent Materializer write.
	if err := w.materializer.Update(ctx, namespace, newRoot, root, delta); err != nil {
		return nil, &MaterializationWriteFailedError{
			NewRoot:              newRoot,
			Namespace:            namespace,
			OldRoot:              root,
			MaterializationBase:  retryBase,
			MaterializationDelta: delta,
			Cause:                fmt.Errorf("Materializer.Update failed: %w", err),
		}
	}
	if w.freshness != nil {
		w.freshness.markAdvancedLocked(namespace, root, newRoot)
	}

	return &UpdateResult{
		OldRoot:   root,
		NewRoot:   newRoot,
		Path:      canonicalPath,
		OldTarget: oldTarget,
		NewTarget: newTarget,
		Op:        op,
	}, nil
}

// BatchUpdateArcs updates multiple arcs atomically.
//
// Given a structure root and a map of path → newTarget, this method:
//  1. Looks up all current bindings
//  2. Applies semantic.BatchUpdate atomically over the current keyed view
//  3. Applies all updates to Materializer
//
// BatchUpdateArcs is a legacy root-consuming API. Within one process, writers
// that share the same Materializer instance advance (namespace, root) exactly once
// for successful non-no-op calls; later attempts to update the same base root
// return ErrStaleRoot instead of silently forking or overwriting Materializer state.
//
// If any update in the batch fails, the entire operation is rejected and
// no state is modified.
func (w *Writer) BatchUpdateArcs(ctx context.Context, namespace string, root cid.Cid, updates map[string]cid.Cid) (*BatchUpdateResult, error) {
	if !root.Defined() {
		return nil, ErrInvalidRoot
	}
	if w.freshnessErr != nil {
		return nil, w.freshnessErr
	}
	if len(updates) == 0 {
		return nil, fmt.Errorf("updates must not be empty")
	}
	normalizedUpdates, err := canonicalizeUpdateMap(updates)
	if err != nil {
		return nil, err
	}
	if w.freshness != nil {
		unlock, err := w.freshness.beginUpdate(namespace, root)
		if err != nil {
			return nil, err
		}
		defer unlock()
	}

	// Step 1: Get current arc set snapshot
	snapshot, err := w.materializer.Snapshot(ctx, namespace, root)
	if err != nil {
		return nil, fmt.Errorf("Materializer.Snapshot failed: %w", err)
	}
	// Step 2: Look up current bindings and classify operations. The snapshot is
	// still used below to build the Materializer delta, but classification uses
	// BatchGet so backend read failures fail closed while missing paths are
	// represented as cid.Undef.
	perArc := make(map[arcset.Path]UpdateResult, len(normalizedUpdates))
	batchUpdates := make([]mapping.BatchUpdate, 0, len(normalizedUpdates))
	paths := make([]arcset.Path, 0, len(normalizedUpdates))

	for path := range normalizedUpdates {
		paths = append(paths, path)
	}
	oldTargets, err := w.materializer.BatchGet(ctx, namespace, root, paths)
	if err != nil {
		return nil, fmt.Errorf("Materializer.BatchGet failed: %w", err)
	}

	for path, newTarget := range normalizedUpdates {
		oldTarget, ok := oldTargets[path]
		if !ok {
			oldTarget = cid.Undef
		}

		isInsert := !oldTarget.Defined() && newTarget.Defined()
		isDelete := oldTarget.Defined() && !newTarget.Defined()

		var op ArcOp
		if isInsert {
			op = ArcInsert
		} else if oldTarget.Defined() && newTarget.Defined() {
			op = ArcReplace
		} else if isDelete {
			op = ArcDelete
		}

		perArc[path] = UpdateResult{
			OldRoot:   root,
			OldTarget: oldTarget,
			NewTarget: newTarget,
			Op:        op,
			Path:      path,
		}

		// Add to batch update list
		batchUpdates = append(batchUpdates, mapping.BatchUpdate{
			Key:      path,
			OldValue: oldTarget,
			NewValue: newTarget,
		})
	}

	// Step 3: Apply batch update atomically
	newRoot, err := w.semantic.BatchUpdate(ctx, namespace, root, batchUpdates)
	if err != nil {
		return nil, fmt.Errorf("semantic.BatchUpdate failed: %w", err)
	}

	oldArcs, err := arcset.ToPathMap(snapshot)
	if err != nil {
		return nil, err
	}
	updatedArcs := make(map[arcset.Path]cid.Cid, len(oldArcs)+len(normalizedUpdates))
	for path, target := range oldArcs {
		updatedArcs[path] = target
	}
	for path, newTarget := range normalizedUpdates {
		if newTarget.Defined() {
			updatedArcs[path] = newTarget
		} else {
			delete(updatedArcs, path)
		}
	}

	delta, err := diffArcMaps(oldArcs, updatedArcs)
	if err != nil {
		return nil, err
	}
	retryBase, err := materializationRetryBase(ctx, w.materializer, namespace)
	if err != nil {
		return nil, &MaterializationWriteFailedError{
			NewRoot:              newRoot,
			Namespace:            namespace,
			OldRoot:              root,
			MaterializationDelta: delta,
			Cause:                fmt.Errorf("Materializer.Snapshot retry base failed: %w", err),
		}
	}

	// Step 4: Apply the update delta to Materializer. On failure the newRoot is
	// semantically valid but its index entries are missing; surface it so the
	// caller can retry the idempotent write.
	if err := w.materializer.Update(ctx, namespace, newRoot, root, delta); err != nil {
		return nil, &MaterializationWriteFailedError{
			NewRoot:              newRoot,
			Namespace:            namespace,
			OldRoot:              root,
			MaterializationBase:  retryBase,
			MaterializationDelta: delta,
			Cause:                fmt.Errorf("Materializer.Update failed: %w", err),
		}
	}
	if w.freshness != nil {
		w.freshness.markAdvancedLocked(namespace, root, newRoot)
	}

	// Update NewRoot for all per-arc results
	for path := range perArc {
		r := perArc[path]
		r.NewRoot = newRoot
		perArc[path] = r
	}

	return &BatchUpdateResult{
		OldRoot: root,
		NewRoot: newRoot,
		PerArc:  perArc,
	}, nil
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
	if w.freshness != nil {
		w.freshness.markCurrent(namespace, root)
	}

	return root, nil
}

// GetArc retrieves the current target CID for an arc path.
//
// This is a read-through operation that delegates to Materializer.
// Returns ErrArcNotFound if the path does not exist.
func (w *Writer) GetArc(ctx context.Context, namespace string, root cid.Cid, path string) (cid.Cid, error) {
	if !root.Defined() {
		return cid.Undef, ErrInvalidRoot
	}
	canonicalPath := arcset.CanonicalizePath(path)
	if canonicalPath.IsEmpty() {
		return cid.Undef, ErrEmptyPath
	}

	target, err := w.materializer.Get(ctx, namespace, root, canonicalPath)
	if err != nil {
		if errors.Is(err, arcset.ErrNotFound) {
			return cid.Undef, fmt.Errorf("%s: %w", canonicalPath.String(), ErrArcNotFound)
		}
		return cid.Undef, fmt.Errorf("Materializer.Get failed: %w", err)
	}

	return target, nil
}

// GetSnapshot retrieves the current arc set snapshot for a structure root.
func (w *Writer) GetSnapshot(ctx context.Context, namespace string, root cid.Cid) (arcset.ArcSet, error) {
	if !root.Defined() {
		return nil, ErrInvalidRoot
	}

	snapshot, err := w.materializer.Snapshot(ctx, namespace, root)
	if err != nil {
		return nil, fmt.Errorf("Materializer.Snapshot failed: %w", err)
	}

	return filterLogicalArcSet(snapshot)
}

package engine

import (
	"context"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/tree"
	"github.com/dewebprotocol/malt-core/maltcid"
	cid "github.com/ipfs/go-cid"
)

func (e *Engine) Prove(ctx context.Context, root cid.Cid, query []byte, source materializer.NodeLookup) (Result, error) {
	if err := e.CheckRoot(root); err != nil {
		return Result{}, err
	}
	d, _, _ := maltcid.ParseRoot(root)
	k, err := e.coordinate(d, query)
	if err != nil {
		return Result{}, err
	}
	return e.Tree.Prove(ctx, root, k, source)
}
func (e *Engine) Verify(root cid.Cid, query []byte, result Result) (bool, error) {
	if err := e.CheckRoot(root); err != nil {
		return false, err
	}
	d, _, _ := maltcid.ParseRoot(root)
	k, err := e.coordinate(d, query)
	if err != nil {
		return false, err
	}
	return e.Tree.Verify(root, k, result)
}
func (e *Engine) Apply(ctx context.Context, root cid.Cid, changes []Change, source materializer.NodeLookup, out materializer.NodeUpdater) (cid.Cid, error) {
	if err := e.CheckRoot(root); err != nil {
		return cid.Undef, err
	}
	d, _, _ := maltcid.ParseRoot(root)
	derived := make([]tree.Change, len(changes))
	for i, c := range changes {
		k, err := e.coordinate(d, c.Label)
		if err != nil {
			return cid.Undef, err
		}
		derived[i] = tree.Change{Coordinate: k, Before: c.Before, After: c.After}
	}
	return e.Tree.Apply(ctx, root, derived, source, out)
}
func (e *Engine) Append(ctx context.Context, root cid.Cid, target cid.Cid, totalSize *uint64, source materializer.NodeLookup, out materializer.NodeUpdater) (cid.Cid, uint64, error) {
	if err := e.CheckRoot(root); err != nil {
		return cid.Undef, 0, err
	}
	return e.Tree.Append(ctx, root, target, totalSize, source, out)
}

// AppendBatch appends a contiguous suffix in one tree edit and returns its first index.
func (e *Engine) AppendBatch(ctx context.Context, root cid.Cid, targets []cid.Cid, totalSize *uint64, source materializer.NodeLookup, out materializer.NodeUpdater) (cid.Cid, uint64, error) {
	if err := e.CheckRoot(root); err != nil {
		return cid.Undef, 0, err
	}
	return e.Tree.AppendBatch(ctx, root, targets, totalSize, source, out)
}
func (e *Engine) Truncate(ctx context.Context, root cid.Cid, count uint64, source materializer.NodeLookup, out materializer.NodeUpdater) (cid.Cid, error) {
	if err := e.CheckRoot(root); err != nil {
		return cid.Undef, err
	}
	return e.Tree.Truncate(ctx, root, count, source, out)
}
func (e *Engine) ResizeMeasured(ctx context.Context, root cid.Cid, count, totalSize uint64, source materializer.NodeLookup, out materializer.NodeUpdater) (cid.Cid, error) {
	if err := e.CheckRoot(root); err != nil {
		return cid.Undef, err
	}
	return e.Tree.ResizeMeasured(ctx, root, count, totalSize, source, out)
}
func (e *Engine) Snapshot(ctx context.Context, root cid.Cid, source materializer.NodeLookup) (View, error) {
	if err := e.CheckRoot(root); err != nil {
		return View{}, err
	}
	return e.Tree.Snapshot(ctx, root, source)
}
func (e *Engine) SnapshotBounded(ctx context.Context, root cid.Cid, source materializer.NodeLookup, maxBindings uint64) (View, error) {
	if err := e.CheckRoot(root); err != nil {
		return View{}, err
	}
	return e.Tree.SnapshotBounded(ctx, root, source, maxBindings)
}
func (e *Engine) ReadMetadata(ctx context.Context, root cid.Cid, source materializer.NodeLookup) (Metadata, Result, error) {
	if err := e.CheckRoot(root); err != nil {
		return Metadata{}, Result{}, err
	}
	return e.Tree.ReadMetadata(ctx, root, source)
}
func (e *Engine) ProveRange(ctx context.Context, root cid.Cid, start uint64, end *uint64, source materializer.NodeLookup) (RangeResult, error) {
	if err := e.CheckRoot(root); err != nil {
		return RangeResult{}, err
	}
	return e.Tree.ProveRange(ctx, root, start, end, source)
}
func (e *Engine) VerifyRange(root cid.Cid, start uint64, end *uint64, result RangeResult) (bool, error) {
	if err := e.CheckRoot(root); err != nil {
		return false, err
	}
	return e.Tree.VerifyRange(root, start, end, result)
}
func (e *Engine) ValidateNode(ctx context.Context, ref maltcid.NodeRef, cells []commitment.Cell) error {
	return e.Tree.ValidateNode(ctx, ref, cells)
}

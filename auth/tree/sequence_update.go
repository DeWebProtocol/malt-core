package tree

import (
	"context"
	"errors"
	"math"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

func (u *nodeEdit) sequence(ref maltcid.NodeRef, expected *Metadata) ([]commitment.Cell, Metadata, error) {
	if u.descriptor.Layout != maltcid.Positional {
		return nil, Metadata{}, errors.New("sequence operation requires Positional")
	}
	cells, err := u.GetNode(u.ctx, ref)
	if err != nil {
		return nil, Metadata{}, err
	}
	meta, err := parseMetadata(cells[0])
	if err != nil {
		return nil, meta, err
	}
	return cells, meta, checkMetadata(meta, expected, u.profile.Slots)
}

// Append adds one position and copies only its path. A measured sequence
// requires the new total size and a previously full final chunk. A plain
// sequence requires nil totalSize. It returns the new candidate and index.
func (e *Engine) Append(ctx context.Context, root cid.Cid, target cid.Cid, totalSize *uint64, source materializer.NodeLookup, out materializer.NodeUpdater) (cid.Cid, uint64, error) {
	return e.AppendBatch(ctx, root, []cid.Cid{target}, totalSize, source, out)
}

// AppendBatch adds a nonempty contiguous suffix, committing each changed or
// new node once. It has the same measurement requirements as Append and returns
// the first appended index. Unchanged subtrees retain their references.
func (e *Engine) AppendBatch(ctx context.Context, root cid.Cid, targets []cid.Cid, totalSize *uint64, source materializer.NodeLookup, out materializer.NodeUpdater) (cid.Cid, uint64, error) {
	u, ref, err := e.edit(ctx, root, source, out)
	if err != nil {
		return cid.Undef, 0, err
	}
	_, meta, err := u.sequence(ref, nil)
	if err != nil {
		return cid.Undef, 0, err
	}
	if len(targets) == 0 || uint64(len(targets)) > math.MaxUint64-meta.Count {
		return cid.Undef, 0, errors.New("empty append batch or sequence length overflow")
	}
	items := make([]binding, len(targets))
	for i, target := range targets {
		if err := ctx.Err(); err != nil {
			return cid.Undef, 0, err
		}
		if !target.Defined() {
			return cid.Undef, 0, errors.New("undefined append target")
		}
		items[i] = binding{target: target}
	}
	next := meta
	next.Count += uint64(len(items))
	if meta.ChunkSize == 0 {
		if totalSize != nil {
			return cid.Undef, 0, ErrNotMeasured
		}
	} else {
		if totalSize == nil {
			return cid.Undef, 0, errors.New("measured append requires new total size")
		}
		if meta.Count > math.MaxUint64/meta.ChunkSize || meta.TotalSize != meta.Count*meta.ChunkSize {
			return cid.Undef, 0, errors.New("cannot append after a partial measured chunk")
		}
		next.TotalSize = *totalSize
	}
	if err := next.validate(); err != nil {
		return cid.Undef, 0, err
	}
	next.Height, err = height(next.Count, uint64(u.profile.Slots-1))
	if err != nil {
		return cid.Undef, 0, err
	}
	b := u.builder
	b.out = u
	ref, err = u.appendNode(&b, ref, meta, next, items)
	if err != nil {
		return cid.Undef, 0, err
	}
	root, err = u.finish(ref)
	return root, meta.Count, err
}
func (u *nodeEdit) appendNode(b *builder, ref maltcid.NodeRef, old, next Metadata, items []binding) (maltcid.NodeRef, error) {
	if old == next {
		return ref, nil
	}
	if old.Count == 0 {
		return b.positional(items, next)
	}
	var cells []commitment.Cell
	var err error
	if next.Height == old.Height {
		cells, _, err = u.sequence(ref, &old)
		if err != nil {
			return maltcid.NodeRef{}, err
		}
	} else {
		// A batch may grow several levels. Recurse into the first child with
		// the old root until its existing height is reached.
		cells = make([]commitment.Cell, u.profile.Slots)
	}
	cells[0] = next.cell()
	if next.Height == 0 {
		for i, item := range items {
			slot := int(old.Count) + i + 1
			if len(cells[slot]) != 0 {
				return maltcid.NodeRef{}, errors.New("nonempty Positional append slot")
			}
			cells[slot] = append(commitment.Cell{positionalLeaf}, item.target.Bytes()...)
		}
		return b.commit(cells)
	}
	span, err := subtreeSpan(next.Height, uint64(u.profile.Slots-1))
	if err != nil {
		return maltcid.NodeRef{}, err
	}
	for slot := 1; slot < len(cells); slot++ {
		if uint64(slot-1) > next.Count/span || uint64(slot-1)*span >= next.Count {
			break
		}
		start := uint64(slot-1) * span
		childMeta, _, err := childMetadata(next, start, u.profile.Slots)
		if err != nil {
			return maltcid.NodeRef{}, err
		}
		var child maltcid.NodeRef
		if start >= old.Count {
			if len(cells[slot]) != 0 {
				return maltcid.NodeRef{}, errors.New("nonempty Positional append slot")
			}
			child, err = b.positional(items[:childMeta.Count], childMeta)
			items = items[childMeta.Count:]
		} else {
			oldChild := old
			child = ref
			if next.Height == old.Height {
				child, err = parseChild(cells[slot], ref)
				if err != nil {
					return maltcid.NodeRef{}, err
				}
				oldChild, _, err = childMetadata(old, start, u.profile.Slots)
				if err != nil {
					return maltcid.NodeRef{}, err
				}
			}
			added := childMeta.Count - oldChild.Count
			child, err = u.appendNode(b, child, oldChild, childMeta, items[:added])
			items = items[added:]
		}
		if err != nil {
			return maltcid.NodeRef{}, err
		}
		cells[slot], err = childCell(child)
		if err != nil {
			return maltcid.NodeRef{}, err
		}
	}
	return b.commit(cells)
}

// Truncate removes a suffix from a plain sequence. Measured truncation needs
// an application-level payload decision and is intentionally not inferred.
func (e *Engine) Truncate(ctx context.Context, root cid.Cid, count uint64, source materializer.NodeLookup, out materializer.NodeUpdater) (cid.Cid, error) {
	return e.resize(ctx, root, count, nil, source, out)
}

// ResizeMeasured removes a suffix or changes the final chunk's measured size.
// The application must explicitly supply the new size and update any changed
// payload target separately; the engine never infers content bytes.
func (e *Engine) ResizeMeasured(ctx context.Context, root cid.Cid, count, totalSize uint64, source materializer.NodeLookup, out materializer.NodeUpdater) (cid.Cid, error) {
	return e.resize(ctx, root, count, &totalSize, source, out)
}

func (e *Engine) resize(ctx context.Context, root cid.Cid, count uint64, totalSize *uint64, source materializer.NodeLookup, out materializer.NodeUpdater) (cid.Cid, error) {
	u, ref, err := e.edit(ctx, root, source, out)
	if err != nil {
		return cid.Undef, err
	}
	_, old, err := u.sequence(ref, nil)
	if err != nil {
		return cid.Undef, err
	}
	if (old.ChunkSize != 0) != (totalSize != nil) {
		return cid.Undef, errors.New("truncate requires a plain Positional sequence")
	}
	if count > old.Count {
		return cid.Undef, errors.New("truncate cannot extend a sequence")
	}
	if count == old.Count && (totalSize == nil || *totalSize == old.TotalSize) {
		return root, nil
	}
	next := Metadata{Count: count, ChunkSize: old.ChunkSize}
	if totalSize != nil {
		next.TotalSize = *totalSize
	}
	if err := next.validate(); err != nil {
		return cid.Undef, err
	}
	next.Height, err = height(count, uint64(u.profile.Slots-1))
	if err != nil {
		return cid.Undef, err
	}
	b := u.builder
	b.out = u
	if count == 0 {
		ref, err = b.positional(nil, next)
	} else {
		for old.Height > next.Height {
			cells, _, loadErr := u.sequence(ref, &old)
			if loadErr != nil {
				return cid.Undef, loadErr
			}
			child, childErr := parseChild(cells[1], ref)
			if childErr != nil {
				return cid.Undef, childErr
			}
			old, _, err = childMetadata(old, 0, u.profile.Slots)
			if err != nil {
				return cid.Undef, err
			}
			ref = child
		}
		ref, err = u.truncateNode(&b, ref, old, next)
	}
	if err != nil {
		return cid.Undef, err
	}
	return u.finish(ref)
}
func (u *nodeEdit) truncateNode(b *builder, ref maltcid.NodeRef, old, next Metadata) (maltcid.NodeRef, error) {
	cells, _, err := u.sequence(ref, &old)
	if err != nil {
		return maltcid.NodeRef{}, err
	}
	if old == next {
		return ref, nil
	}
	cells[0] = next.cell()
	span, err := subtreeSpan(old.Height, uint64(u.profile.Slots-1))
	if err != nil {
		return maltcid.NodeRef{}, err
	}
	for slot := 1; slot < len(cells); slot++ {
		// Division avoids overflow for a maximal-height virtual sequence.
		if uint64(slot-1) > next.Count/span || uint64(slot-1)*span >= next.Count {
			cells[slot] = nil
			continue
		}
		start := uint64(slot-1) * span
		if old.Height == 0 {
			continue
		}
		child, err := parseChild(cells[slot], ref)
		if err != nil {
			return maltcid.NodeRef{}, err
		}
		oldChild, _, err := childMetadata(old, start, u.profile.Slots)
		if err != nil {
			return maltcid.NodeRef{}, err
		}
		nextChild, _, err := childMetadata(next, start, u.profile.Slots)
		if err != nil {
			return maltcid.NodeRef{}, err
		}
		if oldChild == nextChild {
			continue
		}
		child, err = u.truncateNode(b, child, oldChild, nextChild)
		if err != nil {
			return maltcid.NodeRef{}, err
		}
		cells[slot], err = childCell(child)
		if err != nil {
			return maltcid.NodeRef{}, err
		}
	}
	return b.commit(cells)
}

package tree

import (
	"context"
	"errors"
	"math"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/coordinate"
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
	u, ref, err := e.edit(ctx, root, source, out)
	if err != nil {
		return cid.Undef, 0, err
	}
	_, meta, err := u.sequence(ref, nil)
	if err != nil {
		return cid.Undef, 0, err
	}
	if !target.Defined() || meta.Count == math.MaxUint64 {
		return cid.Undef, 0, errors.New("undefined target or sequence length overflow")
	}
	next := meta
	next.Count++
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
	ref, err = u.appendNode(&b, ref, meta, next, target)
	if err != nil {
		return cid.Undef, 0, err
	}
	root, err = u.finish(ref)
	return root, meta.Count, err
}
func (u *nodeEdit) appendNode(b *builder, ref maltcid.NodeRef, old, next Metadata, target cid.Cid) (maltcid.NodeRef, error) {
	cells, _, err := u.sequence(ref, &old)
	if err != nil {
		return maltcid.NodeRef{}, err
	}
	if next.Height > old.Height {
		cells = make([]commitment.Cell, u.profile.Slots)
		cells[1], err = childCell(ref)
		if err != nil {
			return maltcid.NodeRef{}, err
		}
	}
	cells[0] = next.cell()
	span, err := subtreeSpan(next.Height, uint64(u.profile.Slots-1))
	if err != nil {
		return maltcid.NodeRef{}, err
	}
	index := next.Count - 1
	slot := int(index/span) + 1
	if next.Height == 0 {
		if len(cells[slot]) != 0 {
			return maltcid.NodeRef{}, errors.New("nonempty Positional append slot")
		}
		cells[slot] = append(commitment.Cell{positionalLeaf}, target.Bytes()...)
	} else {
		childMeta, _, err := childMetadata(next, index, u.profile.Slots)
		if err != nil {
			return maltcid.NodeRef{}, err
		}
		var child maltcid.NodeRef
		if len(cells[slot]) == 0 {
			if childMeta.Count != 1 {
				return maltcid.NodeRef{}, errors.New("missing prior Positional child")
			}
			child, err = b.positional([]binding{{coordinate: coordinate.Value{Kind: coordinate.Index}, target: target}}, childMeta)
		} else {
			child, err = parseChild(cells[slot], ref)
			if err != nil {
				return maltcid.NodeRef{}, err
			}
			oldChild, _, childErr := childMetadata(old, index-1, u.profile.Slots)
			if childErr != nil {
				return maltcid.NodeRef{}, childErr
			}
			child, err = u.appendNode(b, child, oldChild, childMeta, target)
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

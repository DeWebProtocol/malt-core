package tree

import (
	"context"
	"errors"
	"math"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/maltcid"
	cid "github.com/ipfs/go-cid"
)

func (u *nodeEdit) sequence(ref maltcid.NodeRef) ([]commitment.Cell, Metadata, error) {
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
	return cells, meta, checkPosition(cells, rootPosition(meta.Count, u.profile.Slots), u.profile.Slots)
}

// Append preserves the opaque payload reference and returns the new index.
func (e *Engine) Append(ctx context.Context, root cid.Cid, target cid.Cid, source materializer.NodeLookup, out materializer.NodeUpdater) (cid.Cid, uint64, error) {
	return e.AppendBatch(ctx, root, []cid.Cid{target}, source, out)
}

// AppendBatch builds each final affected node once, including growth across
// multiple levels. Unchanged descendant vectors retain their references.
func (e *Engine) AppendBatch(ctx context.Context, root cid.Cid, targets []cid.Cid, source materializer.NodeLookup, out materializer.NodeUpdater) (cid.Cid, uint64, error) {
	u, ref, err := e.edit(ctx, root, source, out)
	if err != nil {
		return cid.Undef, 0, err
	}
	_, meta, err := u.sequence(ref)
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
	first := meta.Count
	old := rootPosition(first, u.profile.Slots)
	meta.Count += uint64(len(items))
	next := rootPosition(meta.Count, u.profile.Slots)
	b := u.builder
	b.out = u
	ref, err = u.appendNode(&b, ref, old, next, meta, items)
	if err != nil {
		return cid.Undef, 0, err
	}
	root, err = u.finish(ref)
	return root, first, err
}

func (u *nodeEdit) appendNode(b *builder, ref maltcid.NodeRef, old, next position, meta Metadata, items []binding) (maltcid.NodeRef, error) {
	if old == next {
		return ref, nil
	}
	if old.count == 0 {
		return b.positionalNode(items, next, meta)
	}
	cells := make([]commitment.Cell, u.profile.Slots)
	var previous []commitment.Cell
	if old.height == next.height {
		var err error
		previous, err = u.GetNode(u.ctx, ref)
		if err != nil {
			return maltcid.NodeRef{}, err
		}
		if err := checkPosition(previous, old, u.profile.Slots); err != nil {
			return maltcid.NodeRef{}, err
		}
		// Demoting a root reclaims slot zero and shifts only this vector.
		copy(cells[next.base():], previous[old.base():])
	}
	if next.root {
		cells[0] = meta.cell()
	}
	if next.height == 0 {
		for i, item := range items {
			cells[next.base()+int(old.count)+i] = append(commitment.Cell{positionalLeaf}, item.target.Bytes()...)
		}
		return b.commit(cells)
	}
	for digit := 0; digit < next.used(u.profile.Slots); digit++ {
		childPos, start := next.child(digit, u.profile.Slots)
		var child maltcid.NodeRef
		var err error
		if start >= old.count {
			child, err = b.positionalNode(items[:childPos.count], childPos, Metadata{})
			items = items[childPos.count:]
		} else {
			oldChild := old
			child = ref
			if next.height == old.height {
				child, err = parseChild(previous[old.base()+digit], ref)
				if err != nil {
					return maltcid.NodeRef{}, err
				}
				oldChild, _ = old.child(digit, u.profile.Slots)
			}
			added := childPos.count - oldChild.count
			child, err = u.appendNode(b, child, oldChild, childPos, Metadata{}, items[:added])
			items = items[added:]
		}
		if err != nil {
			return maltcid.NodeRef{}, err
		}
		cells[next.base()+digit], err = childCell(child)
		if err != nil {
			return maltcid.NodeRef{}, err
		}
	}
	return b.commit(cells)
}

// Truncate removes a suffix and preserves PayloadCID, including at count zero.
func (e *Engine) Truncate(ctx context.Context, root cid.Cid, count uint64, source materializer.NodeLookup, out materializer.NodeUpdater) (cid.Cid, error) {
	u, ref, err := e.edit(ctx, root, source, out)
	if err != nil {
		return cid.Undef, err
	}
	_, meta, err := u.sequence(ref)
	if err != nil {
		return cid.Undef, err
	}
	if count > meta.Count {
		return cid.Undef, errors.New("truncate cannot extend a sequence")
	}
	if count == meta.Count {
		return root, nil
	}
	old := rootPosition(meta.Count, u.profile.Slots)
	meta.Count = count
	next := rootPosition(count, u.profile.Slots)
	b := u.builder
	b.out = u
	if count == 0 {
		ref, err = b.positional(nil, meta)
	} else {
		for old.height > next.height {
			cells, loadErr := u.GetNode(ctx, ref)
			if loadErr != nil {
				return cid.Undef, loadErr
			}
			if err := checkPosition(cells, old, u.profile.Slots); err != nil {
				return cid.Undef, err
			}
			ref, err = parseChild(cells[old.base()], ref)
			if err != nil {
				return cid.Undef, err
			}
			old, _ = old.child(0, u.profile.Slots)
		}
		ref, err = u.truncateNode(&b, ref, old, next, meta)
	}
	if err != nil {
		return cid.Undef, err
	}
	return u.finish(ref)
}

func (u *nodeEdit) truncateNode(b *builder, ref maltcid.NodeRef, old, next position, meta Metadata) (maltcid.NodeRef, error) {
	if old == next {
		return ref, nil
	}
	previous, err := u.GetNode(u.ctx, ref)
	if err != nil {
		return maltcid.NodeRef{}, err
	}
	if err := checkPosition(previous, old, u.profile.Slots); err != nil {
		return maltcid.NodeRef{}, err
	}
	cells := make([]commitment.Cell, u.profile.Slots)
	if next.root {
		cells[0] = meta.cell()
	}
	for digit := 0; digit < next.used(u.profile.Slots); digit++ {
		cell := previous[old.base()+digit]
		if next.height > 0 {
			oldChild, _ := old.child(digit, u.profile.Slots)
			nextChild, _ := next.child(digit, u.profile.Slots)
			if oldChild != nextChild {
				child, err := parseChild(cell, ref)
				if err != nil {
					return maltcid.NodeRef{}, err
				}
				child, err = u.truncateNode(b, child, oldChild, nextChild, Metadata{})
				if err != nil {
					return maltcid.NodeRef{}, err
				}
				cell, err = childCell(child)
				if err != nil {
					return maltcid.NodeRef{}, err
				}
			}
		}
		cells[next.base()+digit] = cell
	}
	return b.commit(cells)
}

// SetPayload changes only the root's opaque payload reference. Undef removes
// it; a defined CID of empty content remains distinct from no payload.
func (e *Engine) SetPayload(ctx context.Context, root cid.Cid, payload cid.Cid, source materializer.NodeLookup, out materializer.NodeUpdater) (cid.Cid, error) {
	u, ref, err := e.edit(ctx, root, source, out)
	if err != nil {
		return cid.Undef, err
	}
	cells, meta, err := u.sequence(ref)
	if err != nil {
		return cid.Undef, err
	}
	if meta.PayloadCID.Equals(payload) {
		return root, nil
	}
	meta.PayloadCID = payload
	cells[0] = meta.cell()
	b := u.builder
	b.out = u
	ref, err = b.commit(cells)
	if err != nil {
		return cid.Undef, err
	}
	return u.finish(ref)
}

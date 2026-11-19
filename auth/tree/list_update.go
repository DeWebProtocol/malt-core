package tree

import (
	"context"
	"errors"
	"math"
	"sort"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/coordinate"
	"github.com/dewebprotocol/malt-core/maltcid"
	cid "github.com/ipfs/go-cid"
)

func (u *nodeEdit) sequence(ref maltcid.NodeRef) ([]commitment.Cell, Metadata, error) {
	if u.descriptor.Layout != maltcid.List {
		return nil, Metadata{}, errors.New("sequence operation requires List")
	}
	cells, err := u.GetNode(u.ctx, ref)
	if err != nil {
		return nil, Metadata{}, err
	}
	meta, err := parseMetadata(cells[0])
	if err != nil {
		return nil, meta, err
	}
	return cells, meta, checkListGeometry(cells, listRootGeometry(meta.Count, u.profile.Slots), u.profile.Slots)
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
	changes := make([]coordinateChange, len(targets))
	for i, target := range targets {
		if !target.Defined() {
			return cid.Undef, 0, errors.New("undefined append target")
		}
		changes[i] = coordinateChange{key: coordinate.At(meta.Count + uint64(i)), after: target}
	}
	first := meta.Count
	ref, err = u.applyList(ref, meta, changes)
	if err != nil {
		return cid.Undef, 0, err
	}
	root, err = u.finish(ref)
	return root, first, err
}

// Truncate clears every binding at or beyond count. The resulting length
// ends immediately after the last surviving binding, even if the cut falls in a gap.
func (e *Engine) Truncate(ctx context.Context, root cid.Cid, count uint64, source materializer.NodeLookup, out materializer.NodeUpdater) (cid.Cid, error) {
	u, ref, err := e.edit(ctx, root, source, out)
	if err != nil {
		return cid.Undef, err
	}
	cells, meta, err := u.sequence(ref)
	if err != nil {
		return cid.Undef, err
	}
	if count > meta.Count {
		return cid.Undef, errors.New("truncate cannot extend a sequence")
	}
	if count == meta.Count {
		return root, nil
	}
	pos := listRootGeometry(meta.Count, len(cells))
	b := u.builder
	b.out = u
	if err := u.cutList(&b, ref, cells, pos, count); err != nil {
		return cid.Undef, err
	}
	ref, err = u.finishList(&b, ref, cells, pos, meta, true)
	if err != nil {
		return cid.Undef, err
	}
	return u.finish(ref)
}

// Only one boundary subtree can be partly retained by a suffix cut.
func (u *nodeEdit) cutList(b *builder, ref maltcid.NodeRef, cells []commitment.Cell, pos listGeometry, keep uint64) error {
	if keep == 0 {
		clear(cells[pos.base():])
		return nil
	}
	slot := pos.slot(keep-1, len(cells))
	clear(cells[slot+1:])
	if pos.height == 0 || len(cells[slot]) == 0 {
		return nil
	}
	childPos, start := pos.child(slot-pos.base(), len(cells))
	if keep-start == childPos.count {
		return nil
	}
	child, previous, err := u.loadListChild(ref, cells[slot], childPos)
	if err != nil {
		return err
	}
	if err := u.cutList(b, child, previous, childPos, keep-start); err != nil {
		return err
	}
	cells[slot], err = storeListChild(b, previous)
	return err
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

// Reuse the existing child reference unless a changed coordinate enters its interval.
// Growth demotes the old root into the first child and reclaims its metadata slot.
func (u *nodeEdit) applyList(ref maltcid.NodeRef, meta Metadata, items []coordinateChange) (maltcid.NodeRef, error) {
	sort.Slice(items, func(i, j int) bool { return items[i].key.Index < items[j].key.Index })
	old := listRootGeometry(meta.Count, u.profile.Slots)
	recount := false
	for _, item := range items {
		if item.key.Index == math.MaxUint64 {
			return maltcid.NodeRef{}, errors.New("List length overflows uint64")
		}
		if item.after.Defined() {
			meta.Count = max(meta.Count, item.key.Index+1)
		} else if item.key.Index >= old.count {
			return maltcid.NodeRef{}, errors.New("old target does not match authenticated state")
		} else if item.key.Index+1 == old.count {
			recount = true
		}
	}
	next := listRootGeometry(meta.Count, u.profile.Slots)
	b := u.builder
	b.out = u
	cells, err := u.editListCells(&b, ref, old, next, 0, items)
	if err != nil {
		return maltcid.NodeRef{}, err
	}
	return u.finishList(&b, ref, cells, next, meta, recount && next.count == old.count)
}

func (u *nodeEdit) editListCells(b *builder, ref maltcid.NodeRef, old, next listGeometry, offset uint64, items []coordinateChange) ([]commitment.Cell, error) {
	if err := u.ctx.Err(); err != nil {
		return nil, err
	}
	slots := u.profile.Slots
	cells := make([]commitment.Cell, slots)
	if old.count != 0 && old.height == next.height {
		previous, err := u.GetNode(u.ctx, ref)
		if err != nil {
			return nil, err
		}
		if err := checkListGeometry(previous, old, slots); err != nil {
			return nil, err
		}
		copy(cells[next.base():], previous[old.base():])
	}
	if next.height == 0 {
		for _, item := range items {
			slot := next.slot(item.key.Index-offset, slots)
			var target cid.Cid
			if len(cells[slot]) > 0 {
				var err error
				target, err = parseList(cells[slot])
				if err != nil {
					return nil, err
				}
			}
			if err := expect(target, item); err != nil {
				return nil, err
			}
			cells[slot] = nil
			if item.after.Defined() {
				cells[slot] = append(commitment.Cell{listLeaf}, item.after.Bytes()...)
			}
		}
		return cells, nil
	}
	for digit := 0; digit < next.used(slots); digit++ {
		slot := next.base() + digit
		n := 0
		for n < len(items) && next.slot(items[n].key.Index-offset, slots) == slot {
			n++
		}
		demote := digit == 0 && old.count > 0 && old.height < next.height
		if n == 0 && !demote {
			continue
		}
		var prior listGeometry
		childRef := ref
		if demote {
			prior = old
		} else if len(cells[slot]) != 0 {
			prior, _ = old.child(digit, slots)
			var err error
			childRef, err = parseChild(cells[slot], ref)
			if err != nil {
				return nil, err
			}
		}
		childPos, start := next.child(digit, slots)
		updated, err := u.editListCells(b, childRef, prior, childPos, offset+start, items[:n])
		if err != nil {
			return nil, err
		}
		cells[slot], err = storeListChild(b, updated)
		if err != nil {
			return nil, err
		}
		items = items[n:]
	}
	return cells, nil
}

// An unoccupied interval is committed directly as the parent's zero scalar.
func storeListChild(b *builder, cells []commitment.Cell) (commitment.Cell, error) {
	for _, cell := range cells {
		if len(cell) != 0 {
			ref, err := b.commit(cells)
			if err != nil {
				return nil, err
			}
			return childCell(ref)
		}
	}
	return nil, nil
}

func (u *nodeEdit) loadListChild(parent maltcid.NodeRef, cell commitment.Cell, pos listGeometry) (maltcid.NodeRef, []commitment.Cell, error) {
	ref, err := parseChild(cell, parent)
	if err != nil {
		return ref, nil, err
	}
	cells, err := u.GetNode(u.ctx, ref)
	if err != nil {
		return ref, nil, err
	}
	return ref, cells, checkListGeometry(cells, pos, len(cells))
}

// A removed tail may expose an earlier occupied interval. Follow only the
// rightmost surviving path and promote child zero when a shorter root suffices.
func (u *nodeEdit) finishList(b *builder, ref maltcid.NodeRef, cells []commitment.Cell, pos listGeometry, meta Metadata, recount bool) (maltcid.NodeRef, error) {
	if recount {
		pos.tail = false // the previous upper bound is no longer an occupied index
		last, err := u.listLength(ref, cells, pos)
		if err != nil {
			return maltcid.NodeRef{}, err
		}
		meta.Count = last
	}
	slots := u.profile.Slots
	if meta.Count == 0 {
		return b.list(nil, meta)
	}
	next := listRootGeometry(meta.Count, slots)
	for pos.height > next.height {
		child, _ := pos.child(0, slots)
		var err error
		ref, cells, err = u.loadListChild(ref, cells[pos.base()], child)
		if err != nil {
			return maltcid.NodeRef{}, err
		}
		pos = child
	}
	if !pos.root {
		copy(cells[1:], cells[:slots-1])
	}
	cells[0] = meta.cell()
	return b.commit(cells)
}

func (u *nodeEdit) listLength(ref maltcid.NodeRef, cells []commitment.Cell, pos listGeometry) (uint64, error) {
	for slot := len(cells) - 1; slot >= pos.base(); slot-- {
		if len(cells[slot]) == 0 {
			continue
		}
		digit := slot - pos.base()
		if pos.height == 0 {
			return uint64(digit) + 1, nil
		}
		child, start := pos.child(digit, len(cells))
		r, data, err := u.loadListChild(ref, cells[slot], child)
		if err != nil {
			return 0, err
		}
		n, err := u.listLength(r, data, child)
		return start + n, err
	}
	return 0, nil
}

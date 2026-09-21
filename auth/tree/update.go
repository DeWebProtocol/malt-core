package tree

import (
	"bytes"
	"context"
	"errors"
	"sort"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/coordinate"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

// nodeEdit validates each loaded vector once and stages immutable output until
// all expectations have succeeded. Persistent transaction policy stays with
// the caller; an output failure can leave unreachable immutable nodes.
type nodeEdit struct {
	builder
	verifier Profile
	source   materializer.NodeLookup
	loaded   map[string][]commitment.Cell
	pending  []pendingNode
}
type pendingNode struct {
	ref   maltcid.NodeRef
	cells []commitment.Cell
}

func (e *Engine) edit(ctx context.Context, root cid.Cid, source materializer.NodeLookup, out materializer.NodeUpdater) (*nodeEdit, maltcid.NodeRef, error) {
	ref, d, err := maltcid.RootNode(root)
	if err != nil {
		return nil, ref, err
	}
	s, p, err := e.config(d)
	if err != nil {
		return nil, ref, err
	}
	committer, ok := s.(commitment.Committer)
	if !ok {
		return nil, ref, errors.New("VC profile cannot compute commitments")
	}
	if source == nil || out == nil {
		return nil, ref, errors.New("node lookup and updater are required")
	}
	u := &nodeEdit{builder: builder{registry: e.Profiles, ctx: ctx, descriptor: d, profile: p, scheme: committer, out: out}, verifier: s, source: source, loaded: make(map[string][]commitment.Cell)}
	return u, ref, nil
}
func (u *nodeEdit) GetNode(ctx context.Context, ref maltcid.NodeRef) ([]commitment.Cell, error) {
	key, err := ref.Bytes()
	if err != nil {
		return nil, err
	}
	if cells, ok := u.loaded[string(key)]; ok {
		return commitment.CloneCells(cells), nil
	}
	cells, err := u.source.GetNode(ctx, copyNodeRef(ref))
	if err != nil {
		return nil, err
	}
	if w, ok := u.source.(*Workspace); !ok || w.registry != u.registry || w.engine.Profiles != u.registry {
		if _, _, err = openVector(u.verifier, ref, cells, 0); err != nil {
			return nil, err
		}
	}
	u.loaded[string(key)] = commitment.CloneCells(cells)
	return commitment.CloneCells(cells), nil
}
func (u *nodeEdit) PutNode(_ context.Context, ref maltcid.NodeRef, cells []commitment.Cell) error {
	u.pending = append(u.pending, pendingNode{ref, commitment.CloneCells(cells)})
	return nil
}
func (u *nodeEdit) finish(ref maltcid.NodeRef) (cid.Cid, error) {
	root, err := maltcid.NewRoot(u.descriptor, ref.Commitment)
	if err != nil {
		return cid.Undef, err
	}
	for _, node := range u.pending {
		if err := u.ctx.Err(); err != nil {
			return cid.Undef, err
		}
		if err := putComputed(u.ctx, u.builder.out, node.ref, node.cells, u.registry); err != nil {
			return cid.Undef, err
		}
	}
	return root, nil
}

type coordinateChange struct {
	key           coordinate.Value
	before, after cid.Cid
}

// Apply copies only affected authentication paths. Prefix supports insert,
// replace and delete; Positional supports replacement at existing indices.
// Append and Truncate explicitly manage Positional length and metadata.
func (e *Engine) Apply(ctx context.Context, root cid.Cid, changes []Change, source materializer.NodeLookup, out materializer.NodeUpdater) (cid.Cid, error) {
	u, ref, err := e.edit(ctx, root, source, out)
	if err != nil {
		return cid.Undef, err
	}
	b := u.builder
	b.out = u
	items := make([]coordinateChange, 0, len(changes))
	seen := make(map[coordinate.Value]bool)
	for _, change := range changes {
		k, err := checkCoordinate(u.descriptor, change.Coordinate)
		if err != nil {
			return cid.Undef, err
		}
		if seen[k] {
			return cid.Undef, errors.New("duplicate coordinate in update batch")
		}
		seen[k] = true
		if !change.Before.Defined() && !change.After.Defined() {
			return cid.Undef, errors.New("empty update")
		}
		if u.descriptor.Layout == maltcid.Positional && (!change.Before.Defined() || !change.After.Defined()) {
			return cid.Undef, errors.New("Positional Apply requires replacement; use Append or Truncate for length changes")
		}
		items = append(items, coordinateChange{k, change.Before, change.After})
	}
	if len(items) == 0 {
		return root, nil
	}
	if u.descriptor.Layout == maltcid.Prefix {
		sort.Slice(items, func(i, j int) bool { return bytes.Compare(items[i].key.Key[:], items[j].key.Key[:]) < 0 })
		cells, err := u.prefix(&b, ref, 0, items)
		if err != nil {
			return cid.Undef, err
		}
		ref, err = b.commit(cells)
		if err != nil {
			return cid.Undef, err
		}
	} else {
		cells, err := u.GetNode(ctx, ref)
		if err != nil {
			return cid.Undef, err
		}
		meta, err := parseMetadata(cells[0])
		if err != nil {
			return cid.Undef, err
		}
		if err = checkMetadata(meta, nil, u.profile.Slots); err != nil {
			return cid.Undef, err
		}
		for _, item := range items {
			if item.key.Index >= meta.Count {
				return cid.Undef, errors.New("old target does not match authenticated state")
			}
		}
		ref, err = u.replace(&b, ref, meta, 0, items)
		if err != nil {
			return cid.Undef, err
		}
	}
	return u.finish(ref)
}
func expect(actual cid.Cid, item coordinateChange) error {
	if actual.Defined() != item.before.Defined() || actual.Defined() && !actual.Equals(item.before) {
		return errors.New("old target does not match authenticated state")
	}
	return nil
}
func (u *nodeEdit) prefix(b *builder, ref maltcid.NodeRef, depth int, items []coordinateChange) ([]commitment.Cell, error) {
	cells, err := u.GetNode(u.ctx, ref)
	if err != nil {
		return nil, err
	}
	groups := make(map[int][]coordinateChange)
	for _, item := range items {
		slot, err := digit(item.key.Key, depth, u.profile.Slots)
		if err != nil {
			return nil, err
		}
		groups[slot] = append(groups[slot], item)
	}
	for slot := range cells {
		group := groups[slot]
		if len(group) == 0 {
			continue
		}
		old := cells[slot]
		if len(old) > 0 && old[0] == childNode {
			child, err := parseChild(old, ref)
			if err != nil {
				return nil, err
			}
			next, err := u.prefix(b, child, depth+1, group)
			if err != nil {
				return nil, err
			}
			var only commitment.Cell
			count := 0
			for _, cell := range next {
				if len(cell) > 0 {
					only = cell
					count++
				}
			}
			switch {
			case count == 0:
				cells[slot] = nil
			case count == 1 && only[0] == prefixLeaf:
				cells[slot] = only
			default:
				child, err = b.commit(next)
				if err != nil {
					return nil, err
				}
				cells[slot], err = childCell(child)
				if err != nil {
					return nil, err
				}
			}
			continue
		}
		entries := make(map[[32]byte]cid.Cid)
		if len(old) > 0 {
			key, target, err := parsePrefix(old)
			if err != nil {
				return nil, err
			}
			if err := checkLeafRoute(key, group[0].key.Key, depth, u.profile.Slots); err != nil {
				return nil, err
			}
			entries[key] = target
		}
		for _, item := range group {
			if err := expect(entries[item.key.Key], item); err != nil {
				return nil, err
			}
			if item.after.Defined() {
				entries[item.key.Key] = item.after
			} else {
				delete(entries, item.key.Key)
			}
		}
		bindings := make([]binding, 0, len(entries))
		for key, target := range entries {
			bindings = append(bindings, binding{coordinate: coordinate.Value{Kind: coordinate.Key, Key: key}, target: target})
		}
		sort.Slice(bindings, func(i, j int) bool {
			return bytes.Compare(bindings[i].coordinate.Key[:], bindings[j].coordinate.Key[:]) < 0
		})
		switch len(bindings) {
		case 0:
			cells[slot] = nil
		case 1:
			cells[slot] = prefixCell(bindings[0])
		default:
			child, err := b.prefix(bindings, depth+1)
			if err != nil {
				return nil, err
			}
			cells[slot], err = childCell(child)
			if err != nil {
				return nil, err
			}
		}
	}
	return cells, nil
}
func (u *nodeEdit) replace(b *builder, ref maltcid.NodeRef, meta Metadata, offset uint64, items []coordinateChange) (maltcid.NodeRef, error) {
	cells, err := u.GetNode(u.ctx, ref)
	if err != nil {
		return maltcid.NodeRef{}, err
	}
	got, err := parseMetadata(cells[0])
	if err != nil {
		return maltcid.NodeRef{}, err
	}
	if got != meta {
		return maltcid.NodeRef{}, errors.New("child metadata does not match parent")
	}
	span, err := subtreeSpan(meta.Height, uint64(u.profile.Slots-1))
	if err != nil {
		return maltcid.NodeRef{}, err
	}
	groups := make(map[int][]coordinateChange)
	for _, item := range items {
		slot := int((item.key.Index-offset)/span) + 1
		groups[slot] = append(groups[slot], item)
	}
	for slot := 1; slot < len(cells); slot++ {
		group := groups[slot]
		if len(group) == 0 {
			continue
		}
		if meta.Height == 0 {
			target, err := parsePositional(cells[slot])
			if err != nil {
				return maltcid.NodeRef{}, err
			}
			if err = expect(target, group[0]); err != nil {
				return maltcid.NodeRef{}, err
			}
			cells[slot] = append(commitment.Cell{positionalLeaf}, group[0].after.Bytes()...)
		} else {
			child, err := parseChild(cells[slot], ref)
			if err != nil {
				return maltcid.NodeRef{}, err
			}
			childMeta, _, err := childMetadata(meta, uint64(slot-1)*span, u.profile.Slots)
			if err != nil {
				return maltcid.NodeRef{}, err
			}
			child, err = u.replace(b, child, childMeta, offset+uint64(slot-1)*span, group)
			if err != nil {
				return maltcid.NodeRef{}, err
			}
			cells[slot], err = childCell(child)
			if err != nil {
				return maltcid.NodeRef{}, err
			}
		}
	}
	return b.commit(cells)
}

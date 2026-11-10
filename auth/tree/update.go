package tree

import (
	"bytes"
	"context"
	"errors"
	"sort"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/coordinate"
	"github.com/dewebprotocol/malt-core/maltcid"
	cid "github.com/ipfs/go-cid"
)

// nodeEdit validates each loaded vector once and stages immutable output until
// all expectations have succeeded. Persistent transaction policy stays with
// the caller; an output failure can leave unreachable immutable nodes.
type nodeEdit struct {
	builder
	tree     *Engine
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
	u := &nodeEdit{builder: builder{registry: e.Profiles, ctx: ctx, descriptor: d, profile: p, scheme: committer, out: out}, tree: e, verifier: s, source: source, loaded: make(map[string][]commitment.Cell)}
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
	key           coordinate.Coordinate
	label         []byte
	before, after cid.Cid
}

// Apply copies only affected authentication paths. Map supports insert,
// replace and delete; List supports replacement at existing indices.
// Append and Truncate explicitly manage List length and metadata.
func (e *Engine) Apply(ctx context.Context, root cid.Cid, changes []Change, source materializer.NodeLookup, out materializer.NodeUpdater) (cid.Cid, error) {
	u, ref, err := e.edit(ctx, root, source, out)
	if err != nil {
		return cid.Undef, err
	}
	b := u.builder
	b.out = u
	items := make([]coordinateChange, 0, len(changes))
	seen := make(map[coordinate.Coordinate][]byte)
	for _, change := range changes {
		k, err := e.selector(u.descriptor, Selector{Coordinate: change.Coordinate, Label: change.Label})
		if err != nil {
			return cid.Undef, err
		}
		if label, exists := seen[k]; exists {
			if !bytes.Equal(label, change.Label) {
				return cid.Undef, ErrCoordinateCollision
			}
			return cid.Undef, errors.New("duplicate coordinate in update batch")
		}
		seen[k] = bytes.Clone(change.Label)
		if !change.Before.Defined() && !change.After.Defined() {
			return cid.Undef, errors.New("empty update")
		}
		if u.descriptor.Layout == maltcid.List && (!change.Before.Defined() || !change.After.Defined()) {
			return cid.Undef, errors.New("List Apply requires replacement; use Append or Truncate for length changes")
		}
		items = append(items, coordinateChange{key: k, label: bytes.Clone(change.Label), before: change.Before, after: change.After})
	}
	if len(items) == 0 {
		return root, nil
	}
	if u.descriptor.Layout == maltcid.Map {
		sort.Slice(items, func(i, j int) bool { return bytes.Compare(items[i].key.Key[:], items[j].key.Key[:]) < 0 })
		cells, err := u.mapNode(&b, ref, 0, items)
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
		for _, item := range items {
			if item.key.Index >= meta.Count {
				return cid.Undef, errors.New("old target does not match authenticated state")
			}
		}
		ref, err = u.replace(&b, ref, listRootGeometry(meta.Count, u.profile.Slots), 0, items)
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

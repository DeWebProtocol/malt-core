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
	pending  map[string]pendingNode
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
	u := &nodeEdit{builder: builder{registry: e.Profiles, ctx: ctx, descriptor: d, profile: p, scheme: committer, out: out}, tree: e, verifier: s, source: source, loaded: make(map[string][]commitment.Cell), pending: make(map[string]pendingNode)}
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
	key, err := ref.Bytes()
	if err != nil {
		return err
	}
	owned := commitment.CloneCells(cells)
	u.loaded[string(key)] = owned
	u.pending[string(key)] = pendingNode{ref, owned}
	return nil
}
func (u *nodeEdit) finish(ref maltcid.NodeRef) (cid.Cid, error) {
	root, err := maltcid.NewRoot(u.descriptor, ref.Commitment)
	if err != nil {
		return cid.Undef, err
	}
	if err := u.writePending(ref); err != nil {
		return cid.Undef, err
	}
	return root, nil
}

// Write each reachable staged node after its children. Shrinking a List may
// promote a staged vector to root and discard its intermediate child encoding.
func (u *nodeEdit) writePending(ref maltcid.NodeRef) error {
	raw, err := ref.Bytes()
	if err != nil {
		return err
	}
	key := string(raw)
	node, ok := u.pending[key]
	if !ok {
		return nil // an unchanged child remains in the base materialization
	}
	if err := u.ctx.Err(); err != nil {
		return err
	}
	delete(u.pending, key)
	for _, cell := range node.cells {
		if len(cell) > 0 && cell[0] == childNode {
			child, err := parseChild(cell, ref)
			if err != nil {
				return err
			}
			if err := u.writePending(child); err != nil {
				return err
			}
		}
	}
	return putComputed(u.ctx, u.builder.out, node.ref, node.cells, u.registry)
}

type coordinateChange struct {
	key           coordinate.Coordinate
	label         []byte
	before, after cid.Cid
}

// Apply inserts, replaces or clears bindings along the affected paths.
// Clearing a List index preserves the coordinates of all surviving bindings.
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
		_, meta, err := u.sequence(ref)
		if err != nil {
			return cid.Undef, err
		}
		ref, err = u.applyList(ref, meta, items)
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

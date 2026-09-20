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

// Materialization owns immutable vectors in a closed DAG. Child pointers share
// unchanged subtrees; they never retain obsolete ancestors or earlier versions.
// Its vectors are either checked at import or computed by the installed backend.
// It is local computation state, not a portable transition proof.
type Materialization struct {
	registry *Registry
	root     cid.Cid
	node     *retainedNode
}
type retainedNode struct {
	charge   uint64
	ref      maltcid.NodeRef
	cells    []commitment.Cell
	children []*retainedNode
}

func (m *Materialization) Root() cid.Cid { return m.root }

// Workspace is a single-operation materializer. It lazily indexes nodes exposed
// by traversing the base and retains newly produced nodes only until Seal.
// Workspaces are not shared between concurrent operations.
type Workspace struct {
	engine   *Engine
	registry *Registry
	known    map[string]*retainedNode
}

func (e *Engine) Workspace(base *Materialization) (*Workspace, error) {
	if e == nil || e.Profiles == nil {
		return nil, errors.New("tree is not configured")
	}
	w := &Workspace{engine: e, registry: e.Profiles, known: make(map[string]*retainedNode)}
	if base != nil {
		if base.registry != e.Profiles {
			return nil, errors.New("materialization belongs to another profile registry")
		}
		key, err := base.node.ref.Bytes()
		if err != nil {
			return nil, err
		}
		w.known[string(key)] = base.node
	}
	return w, nil
}
func (w *Workspace) GetNode(ctx context.Context, ref maltcid.NodeRef) ([]commitment.Cell, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key, err := ref.Bytes()
	if err != nil {
		return nil, err
	}
	n := w.known[string(key)]
	if n == nil {
		return nil, materializer.ErrIncomplete
	}
	// A tree operation reads a parent before its children. No full-state index
	// needs to be copied when a candidate branches from an immutable base.
	for _, child := range n.children {
		k, _ := child.ref.Bytes()
		w.known[string(k)] = child
	}
	return cloneVector(n.cells), nil
}

// PutNode validates externally supplied vectors. Only this package can use the
// private path for vectors whose commitment it has just computed.
func (w *Workspace) PutNode(ctx context.Context, ref maltcid.NodeRef, cells []commitment.Cell) error {
	if err := w.engine.ValidateNode(ctx, ref, cells); err != nil {
		return err
	}
	return w.putComputed(ctx, ref, cells)
}
func (w *Workspace) putComputed(ctx context.Context, ref maltcid.NodeRef, cells []commitment.Cell) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	key, err := ref.Bytes()
	if err != nil {
		return err
	}
	if old := w.known[string(key)]; old != nil {
		if len(old.cells) != len(cells) {
			return errors.New("conflicting immutable node")
		}
		for i, c := range old.cells {
			if !c.Equal(cells[i]) {
				return errors.New("conflicting immutable node")
			}
		}
		return nil
	}
	n := &retainedNode{ref: ref, cells: cloneVector(cells)}
	n.ref.Commitment = append([]byte(nil), ref.Commitment...)
	for _, cell := range cells {
		if len(cell) == 0 || cell[0] != childNode {
			continue
		}
		child, err := parseChild(cell, ref)
		if err != nil {
			return err
		}
		k, _ := child.Bytes()
		v := w.known[string(k)]
		if v == nil {
			return materializer.ErrIncomplete
		}
		n.children = append(n.children, v)
	}
	n.charge = uint64(256 + len(cells)*32 + len(ref.Commitment)*2)
	for _, cell := range cells {
		n.charge = addCharge(n.charge, uint64(len(cell))*2)
	}
	for _, child := range n.children {
		n.charge = addCharge(n.charge, child.charge)
	}
	w.known[string(key)] = n
	return nil
}

// Seal retains only the selected root and its descendants. Dropping the
// workspace releases temporary paths, including intermediate append roots.
func (w *Workspace) Seal(root cid.Cid) (*Materialization, error) {
	ref, d, err := maltcid.RootNode(root)
	if err != nil {
		return nil, err
	}
	if err := w.engine.CheckDescriptor(d); err != nil {
		return nil, err
	}
	key, _ := ref.Bytes()
	n := w.known[string(key)]
	if n == nil {
		return nil, materializer.ErrIncomplete
	}
	return &Materialization{registry: w.registry, root: root, node: n}, nil
}

// CopyTo explicitly exports each reachable immutable vector once.
func (m *Materialization) CopyTo(ctx context.Context, out materializer.NodeUpdater) error {
	if m == nil || m.node == nil || out == nil {
		return errors.New("materialization and output are required")
	}
	seen := make(map[string]bool)
	var walk func(*retainedNode) error
	walk = func(n *retainedNode) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		key, _ := n.ref.Bytes()
		if seen[string(key)] {
			return nil
		}
		seen[string(key)] = true
		for _, c := range n.children {
			if err := walk(c); err != nil {
				return err
			}
		}
		ref := n.ref
		ref.Commitment = append([]byte(nil), ref.Commitment...)
		return out.PutNode(ctx, ref, cloneVector(n.cells))
	}
	return walk(m.node)
}

// Import validates complete bounded state before creating a retained DAG.
// The returned coordinate view was checked against the selected Root.
func (e *Engine) Import(ctx context.Context, root cid.Cid, source materializer.NodeLookup, maxBindings uint64) (*Materialization, View, error) {
	c := &importNodes{source: source, cells: make(map[string][]commitment.Cell)}
	view, err := e.SnapshotBounded(ctx, root, c, maxBindings)
	if err != nil {
		return nil, View{}, err
	}
	w, err := e.Workspace(nil)
	if err != nil {
		return nil, View{}, err
	}
	ref, _, _ := maltcid.RootNode(root)
	var retain func(maltcid.NodeRef) error
	retain = func(ref maltcid.NodeRef) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		key, _ := ref.Bytes()
		if w.known[string(key)] != nil {
			return nil
		}
		cells, ok := c.cells[string(key)]
		if !ok {
			return materializer.ErrIncomplete
		}
		for _, cell := range cells {
			if len(cell) == 0 || cell[0] != childNode {
				continue
			}
			child, err := parseChild(cell, ref)
			if err != nil {
				return err
			}
			if err := retain(child); err != nil {
				return err
			}
		}
		return w.putComputed(ctx, ref, cells)
	}
	if err := retain(ref); err != nil {
		return nil, View{}, err
	}
	m, err := w.Seal(root)
	return m, view, err
}

type importNodes struct {
	source materializer.NodeLookup
	cells  map[string][]commitment.Cell
}

func (s *importNodes) GetNode(ctx context.Context, ref maltcid.NodeRef) ([]commitment.Cell, error) {
	key, err := ref.Bytes()
	if err != nil {
		return nil, err
	}
	if cells, ok := s.cells[string(key)]; ok {
		return cloneVector(cells), nil
	}
	if s.source == nil {
		return nil, errors.New("node lookup is nil")
	}
	cells, err := s.source.GetNode(ctx, copyNodeRef(ref))
	if err != nil {
		return nil, err
	}
	s.cells[string(key)] = cloneVector(cells)
	return cloneVector(cells), nil
}
func putComputed(ctx context.Context, out materializer.NodeUpdater, ref maltcid.NodeRef, cells []commitment.Cell, registry *Registry) error {
	if w, ok := out.(*Workspace); ok && w.registry == registry && w.engine.Profiles == registry {
		return w.putComputed(ctx, ref, cells)
	}
	return out.PutNode(ctx, copyNodeRef(ref), cloneVector(cells))
}

// StateCharge is a conservative accounting bound for retained vectors. Shared
// descendants are counted at each reference so it is available without scanning.
func (m *Materialization) StateCharge() uint64 { return m.node.charge }
func addCharge(a, b uint64) uint64 {
	if math.MaxUint64-a < b {
		return math.MaxUint64
	}
	return a + b
}

func copyNodeRef(ref maltcid.NodeRef) maltcid.NodeRef {
	ref.Commitment = append([]byte(nil), ref.Commitment...)
	return ref
}

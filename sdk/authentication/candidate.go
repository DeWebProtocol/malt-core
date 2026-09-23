package authentication

import (
	"bytes"
	"context"
	"errors"
	"sort"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/tree"
	"github.com/dewebprotocol/malt-core/engine"
	"github.com/dewebprotocol/malt-core/protocol"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

type vectors struct {
	nodes map[string][]commitment.Cell
	used  map[string]bool
}

func (v *vectors) GetNode(_ context.Context, ref maltcid.NodeRef) ([]commitment.Cell, error) {
	key, err := ref.Bytes()
	if err != nil {
		return nil, err
	}
	cells, ok := v.nodes[string(key)]
	if !ok {
		return nil, materializer.ErrIncomplete
	}
	v.used[string(key)] = true
	return commitment.CloneCells(cells), nil
}
func (v *vectors) PutNode(_ context.Context, ref maltcid.NodeRef, cells []commitment.Cell) error {
	key, err := ref.Bytes()
	if err != nil {
		return err
	}
	if existing, ok := v.nodes[string(key)]; ok {
		if len(existing) != len(cells) {
			return errors.New("conflicting node vector")
		}
		for i, c := range existing {
			if !c.Equal(cells[i]) {
				return errors.New("conflicting node vector")
			}
		}
		return nil
	}
	v.nodes[string(key)] = commitment.CloneCells(cells)
	return nil
}

// Prepare computes a complete candidate locally. Retained input bytes are
// copied so later caller mutations cannot alter it.
func Prepare(ctx context.Context, e *engine.Engine, state engine.State) (protocol.AuthenticationCandidate, error) {
	w, err := BuildWriter(ctx, e, state)
	if err != nil {
		return protocol.AuthenticationCandidate{}, err
	}
	return w.Export(ctx)
}

// ValidateCandidate checks complete materialization at the declared Root by
// root-bound openings. It does not substitute a server-computed commitment.
func ValidateCandidate(ctx context.Context, e *engine.Engine, candidate protocol.AuthenticationCandidate) error {
	_, err := validateCandidate(ctx, e, candidate)
	return err
}
func validateCandidate(ctx context.Context, e *engine.Engine, candidate protocol.AuthenticationCandidate) (*vectors, error) {
	v, _, err := importCandidate(ctx, e, candidate)
	return v, err
}
func importCandidate(ctx context.Context, e *engine.Engine, candidate protocol.AuthenticationCandidate) (*vectors, *tree.Materialization, error) {
	if err := candidate.Validate(); err != nil {
		return nil, nil, err
	}
	root, err := cid.Decode(candidate.Root)
	if err != nil {
		return nil, nil, err
	}
	d, _, err := maltcid.ParseRoot(root)
	if err != nil {
		return nil, nil, err
	}
	profile, err := maltcid.Profile(d.Profile)
	if err != nil {
		return nil, nil, err
	}
	v := &vectors{nodes: make(map[string][]commitment.Cell), used: make(map[string]bool)}
	for _, node := range candidate.Nodes {
		ref, err := maltcid.ParseNodeRef(node.Reference)
		if err != nil {
			return nil, nil, err
		}
		if ref.Layout != d.Layout || ref.Profile != d.Profile || len(node.Cells) != profile.Slots {
			return nil, nil, errors.New("candidate node descriptor/width mismatch")
		}
		key := string(node.Reference)
		if _, ok := v.nodes[key]; ok {
			return nil, nil, errors.New("duplicate candidate node")
		}
		cells := make([]commitment.Cell, len(node.Cells))
		for i, c := range node.Cells {
			cells[i] = commitment.NewCell(c)
		}
		v.nodes[key] = cells
	}
	if err := e.CheckRoot(root); err != nil {
		return nil, nil, err
	}
	nodes, view, err := e.Tree.Import(ctx, root, v, uint64(len(candidate.State.Entries)))
	if err != nil {
		return nil, nil, err
	}
	if err := e.MatchView(candidate.State, view); err != nil {
		return nil, nil, err
	}
	if len(v.used) != len(v.nodes) {
		return nil, nil, errors.New("candidate includes unreachable nodes")
	}
	return v, nodes, nil
}

// Materialize verifies before writing immutable nodes. The caller separately
// persists candidate.State and decides transactions, content dependencies,
// root publication and trust. Partial write failures never report success.
func Materialize(ctx context.Context, e *engine.Engine, candidate protocol.AuthenticationCandidate, out materializer.NodeUpdater) error {
	if out == nil {
		return errors.New("node updater is nil")
	}
	v, err := validateCandidate(ctx, e, candidate)
	if err != nil {
		return err
	}
	for _, node := range candidate.Nodes {
		if err := ctx.Err(); err != nil {
			return err
		}
		ref, err := maltcid.ParseNodeRef(node.Reference)
		if err != nil {
			return err
		}
		if err := out.PutNode(ctx, ref, commitment.CloneCells(v.nodes[string(node.Reference)])); err != nil {
			return err
		}
	}
	return nil
}

// Export returns retained inputs and the complete validated materialization
// without recomputing a commitment. It is an untrusted writer view on the wire.
func Export(ctx context.Context, e *engine.Engine, root cid.Cid, state engine.State, source materializer.NodeLookup) (protocol.AuthenticationCandidate, error) {
	collector := &recordNodes{source: source, vectors: &vectors{nodes: make(map[string][]commitment.Cell), used: make(map[string]bool)}}
	if err := e.ValidateState(ctx, root, state, collector); err != nil {
		return protocol.AuthenticationCandidate{}, err
	}
	candidate := protocol.AuthenticationCandidate{Profile: protocol.AuthenticationProfile, Root: root.String(), State: cloneState(state), Nodes: []protocol.AuthenticationNode{}}
	keys := make([]string, 0, len(collector.nodes))
	for key := range collector.nodes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		node := protocol.AuthenticationNode{Reference: []byte(key), Cells: make([][]byte, len(collector.nodes[key]))}
		for i, c := range collector.nodes[key] {
			node.Cells[i] = bytes.Clone(c)
		}
		candidate.Nodes = append(candidate.Nodes, node)
	}
	return candidate, nil
}

type recordNodes struct {
	source materializer.NodeLookup
	*vectors
}

func (r *recordNodes) GetNode(ctx context.Context, ref maltcid.NodeRef) ([]commitment.Cell, error) {
	// The collector key and the reference validated by Snapshot must remain
	// independent of any mutations made by the external source.
	request := ref
	request.Commitment = bytes.Clone(ref.Commitment)
	cells, err := r.source.GetNode(ctx, request)
	if err != nil {
		return nil, err
	}
	if err := r.PutNode(ctx, ref, cells); err != nil {
		return nil, err
	}
	return cells, nil
}

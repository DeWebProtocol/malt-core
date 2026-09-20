package authentication

import (
	"bytes"
	"context"
	"errors"
	"sort"

	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/engine"
	"github.com/dewebprotocol/malt-core/auth/input"
	"github.com/dewebprotocol/malt-core/auth/tree"
	"github.com/dewebprotocol/malt-core/protocol"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

// Writer retains one verified complete ArcSet. Update creates an independent
// candidate writer, leaving this base usable for retries and branches. Keeping
// or discarding that candidate is local computation, never remote durability,
// publication or trusted-root acceptance. Applications compose child candidates
// before updating their parent bindings.
type Writer struct {
	engine   *engine.Engine
	root     cid.Cid
	previous string
	metadata engine.State
	bindings *bindingNode
	nodes    *tree.Materialization
}

// NewWriter imports and validates a complete untrusted candidate once.
func NewWriter(ctx context.Context, e *engine.Engine, candidate protocol.AuthenticationCandidate) (*Writer, error) {
	candidate = cloneCandidate(candidate)
	_, nodes, err := importCandidate(ctx, e, candidate)
	if err != nil {
		return nil, err
	}
	bindings, _, err := bindingsFromState(ctx, e, candidate.State)
	if err != nil {
		return nil, err
	}
	metadata := candidate.State
	metadata.Entries = nil
	return &Writer{engine: e, root: nodes.Root(), previous: candidate.Previous, metadata: metadata, bindings: bindings, nodes: nodes}, nil
}

// BuildWriter constructs retained state directly, without an export/import round trip.
func BuildWriter(ctx context.Context, e *engine.Engine, state engine.State) (*Writer, error) {
	bindings, view, err := bindingsFromState(ctx, e, state)
	if err != nil {
		return nil, err
	}
	work, err := e.Tree.Workspace(nil)
	if err != nil {
		return nil, err
	}
	root, err := e.Commit(ctx, view, work)
	if err != nil {
		return nil, err
	}
	nodes, err := work.Seal(root)
	if err != nil {
		return nil, err
	}
	state.Entries = nil
	return &Writer{engine: e, root: root, metadata: state, bindings: bindings, nodes: nodes}, nil
}
func (w *Writer) Root() cid.Cid { return w.root }

// Export performs the explicit full-state traversal and copying needed for a
// portable candidate. Owned immutable nodes do not need cryptographic revalidation.
func (w *Writer) Export(ctx context.Context) (protocol.AuthenticationCandidate, error) {
	if w == nil || w.nodes == nil {
		return protocol.AuthenticationCandidate{}, errors.New("writer is not initialized")
	}
	state, err := w.exportState(ctx)
	if err != nil {
		return protocol.AuthenticationCandidate{}, err
	}
	v := &vectors{nodes: make(map[string][]commitment.Cell), used: make(map[string]bool)}
	if err := w.nodes.CopyTo(ctx, v); err != nil {
		return protocol.AuthenticationCandidate{}, err
	}
	candidate := protocol.AuthenticationCandidate{Profile: protocol.AuthenticationProfile, Root: w.root.String(), Previous: w.previous, State: state, Nodes: []protocol.AuthenticationNode{}}
	keys := make([]string, 0, len(v.nodes))
	for k := range v.nodes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if err := ctx.Err(); err != nil {
			return protocol.AuthenticationCandidate{}, err
		}
		node := protocol.AuthenticationNode{Reference: []byte(key), Cells: make([][]byte, len(v.nodes[key]))}
		for i, c := range v.nodes[key] {
			node.Cells[i] = bytes.Clone(c)
		}
		candidate.Nodes = append(candidate.Nodes, node)
	}
	return candidate, nil
}

// Candidate is the synchronous complete export. Use Export for cancellation;
// incremental callers use Root and Apply without exporting at every update.
func (w *Writer) Candidate() protocol.AuthenticationCandidate {
	c, err := w.Export(context.Background())
	if err != nil {
		panic(err)
	}
	return c
}
func (w *Writer) exportState(ctx context.Context) (engine.State, error) {
	state := w.metadata
	state.Entries = []engine.Entry{}
	err := bindingWalk(ctx, w.bindings, func(n *bindingNode) error {
		entry := n.entry
		entry.Input.Data = bytes.Clone(entry.Input.Data)
		state.Entries = append(state.Entries, entry)
		return nil
	})
	return state, err
}

func cloneCandidate(c protocol.AuthenticationCandidate) protocol.AuthenticationCandidate {
	c.State.Entries = append([]engine.Entry{}, c.State.Entries...)
	for i := range c.State.Entries {
		c.State.Entries[i].Input.Data = append([]byte(nil), c.State.Entries[i].Input.Data...)
	}
	c.Nodes = append([]protocol.AuthenticationNode{}, c.Nodes...)
	for i := range c.Nodes {
		c.Nodes[i].Reference = append([]byte(nil), c.Nodes[i].Reference...)
		cells := make([][]byte, len(c.Nodes[i].Cells))
		for j := range cells {
			cells[j] = append([]byte(nil), c.Nodes[i].Cells[j]...)
		}
		c.Nodes[i].Cells = cells
	}
	return c
}

// PrepareUpdate verifies a complete base and computes a candidate using path
// updates. Repeated callers can retain a Writer to avoid re-importing the base.
func PrepareUpdate(ctx context.Context, e *engine.Engine, base protocol.AuthenticationCandidate, state engine.State) (protocol.AuthenticationCandidate, error) {
	w, err := NewWriter(ctx, e, base)
	if err != nil {
		return protocol.AuthenticationCandidate{}, err
	}
	next, err := w.Update(ctx, state)
	if err != nil {
		return protocol.AuthenticationCandidate{}, err
	}
	return next.Export(ctx)
}

// Update accepts complete desired state and compiles it to the same delta path
// used by Apply. Its input scan is necessarily linear; node work is incremental.
func (w *Writer) Update(ctx context.Context, state engine.State) (*Writer, error) {
	if w == nil || w.engine == nil {
		return nil, errors.New("writer is not initialized")
	}
	if state.Descriptor != w.metadata.Descriptor {
		return nil, errors.New("update cannot change Root configuration; prepare a new ArcSet")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if state.ChunkSize != w.metadata.ChunkSize {
		next, err := BuildWriter(ctx, w.engine, state)
		if err != nil {
			return nil, err
		}
		next.previous = w.root.String()
		if next.root.Equals(w.root) {
			next.previous = w.previous
		}
		return next, nil
	}
	view, err := w.engine.Interpret(state)
	if err != nil {
		return nil, err
	}
	desired := make(map[input.Coordinate]bool, len(view.Bindings))
	delta := Delta{}
	for i, b := range view.Bindings {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if desired[b.Coordinate] {
			return nil, errors.New("duplicate desired coordinate")
		}
		if !b.Target.Defined() {
			return nil, errors.New("undefined desired target")
		}
		desired[b.Coordinate] = true
		old := bindingGet(w.bindings, bindingKey(b.Coordinate))
		entry := state.Entries[i]
		if old != nil && old.entry.Target.Equals(b.Target) && old.entry.Input.Kind == entry.Input.Kind && old.entry.Input.Number == entry.Input.Number && bytes.Equal(old.entry.Input.Data, entry.Input.Data) {
			continue
		}
		change := engine.Change{Input: entry.Input, After: b.Target}
		if old != nil {
			change.Before = old.entry.Target
		}
		delta.Changes = append(delta.Changes, change)
	}
	if state.Descriptor.Layout == maltcid.Prefix {
		if state.ChunkSize != 0 || state.TotalSize != 0 {
			return nil, errors.New("Prefix cannot carry sequence metadata")
		}
		if err := bindingWalk(ctx, w.bindings, func(n *bindingNode) error {
			if !desired[n.coordinate] {
				delta.Changes = append(delta.Changes, engine.Change{Input: n.entry.Input, Before: n.entry.Target})
			}
			return nil
		}); err != nil {
			return nil, err
		}
	} else {
		count := uint64(len(state.Entries))
		delta.Count = &count
		for i := uint64(0); i < count; i++ {
			if !desired[input.Coordinate{Kind: input.Index, Index: i}] {
				return nil, errors.New("Positional inputs must be contiguous")
			}
		}
		if state.ChunkSize > 0 {
			delta.TotalSize = &state.TotalSize
		} else if state.TotalSize != 0 {
			return nil, errors.New("plain sequence cannot carry total size")
		}
	}
	return w.Apply(ctx, delta)
}

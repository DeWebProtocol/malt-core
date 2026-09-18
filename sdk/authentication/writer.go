package authentication

import (
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/engine"
	"github.com/dewebprotocol/malt-core/auth/input"
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
	engine    *engine.Engine
	candidate protocol.AuthenticationCandidate
	nodes     *vectors
}

func NewWriter(ctx context.Context, e *engine.Engine, candidate protocol.AuthenticationCandidate) (*Writer, error) {
	candidate = cloneCandidate(candidate)
	nodes, err := validateCandidate(ctx, e, candidate)
	if err != nil {
		return nil, err
	}
	return &Writer{engine: e, candidate: candidate, nodes: nodes}, nil
}

// Candidate returns a detached complete view suitable for materialization.
func (w *Writer) Candidate() protocol.AuthenticationCandidate { return cloneCandidate(w.candidate) }

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
	return next.Candidate(), nil
}

func (w *Writer) Update(ctx context.Context, state engine.State) (*Writer, error) {
	if w == nil || w.engine == nil {
		return nil, errors.New("writer is not initialized")
	}
	if state.Descriptor != w.candidate.State.Descriptor {
		return nil, errors.New("update cannot change Root configuration; prepare a new ArcSet")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	oldView, err := w.engine.Interpret(w.candidate.State)
	if err != nil {
		return nil, err
	}
	newView, err := w.engine.Interpret(state)
	if err != nil {
		return nil, err
	}
	old := make(map[input.Coordinate]int, len(oldView.Bindings))
	for i, b := range oldView.Bindings {
		old[b.Coordinate] = i
	}
	desired := make(map[input.Coordinate]int, len(newView.Bindings))
	for i, b := range newView.Bindings {
		if _, exists := desired[b.Coordinate]; exists {
			return nil, errors.New("duplicate desired coordinate")
		}
		if !b.Target.Defined() {
			return nil, errors.New("undefined desired target")
		}
		desired[b.Coordinate] = i
	}
	nodes := &vectors{nodes: make(map[string][]commitment.Cell), used: make(map[string]bool)}
	// Immutable vectors are shared; PutNode and GetNode copy caller-owned slices.
	for key, cells := range w.nodes.nodes {
		nodes.nodes[key] = cells
	}
	root := cid.MustParse(w.candidate.Root)
	if state.Descriptor.Layout == maltcid.Prefix {
		if state.ChunkSize != 0 || state.TotalSize != 0 {
			return nil, errors.New("Prefix cannot carry sequence metadata")
		}
		changes := []engine.Change{}
		for i, b := range oldView.Bindings {
			j, exists := desired[b.Coordinate]
			if !exists {
				changes = append(changes, engine.Change{Input: w.candidate.State.Entries[i].Input, Before: b.Target})
				continue
			}
			if !b.Target.Equals(newView.Bindings[j].Target) {
				changes = append(changes, engine.Change{Input: state.Entries[j].Input, Before: b.Target, After: newView.Bindings[j].Target})
			}
		}
		for j, b := range newView.Bindings {
			if _, exists := old[b.Coordinate]; !exists {
				changes = append(changes, engine.Change{Input: state.Entries[j].Input, After: b.Target})
			}
		}
		root, err = w.engine.Apply(ctx, root, changes, nodes, nodes)
	} else {
		count := uint64(len(state.Entries))
		oldCount := uint64(len(w.candidate.State.Entries))
		for i := uint64(0); i < count; i++ {
			if _, exists := desired[input.Coordinate{Kind: input.Index, Index: i}]; !exists {
				return nil, errors.New("Positional inputs must be contiguous")
			}
		}
		if state.ChunkSize != w.candidate.State.ChunkSize {
			// A chunk geometry change is a new layout materialization, not a claim of
			// path-only maintenance. Content/rechunking policy belongs to the caller.
			root, err = w.engine.Build(ctx, state, nodes)
		} else {
			changes := []engine.Change{}
			for i := uint64(0); i < min(count, oldCount); i++ {
				k := input.Coordinate{Kind: input.Index, Index: i}
				before, after := oldView.Bindings[old[k]].Target, newView.Bindings[desired[k]].Target
				if !before.Equals(after) {
					changes = append(changes, engine.Change{Input: input.IndexValue(i), Before: before, After: after})
				}
			}
			root, err = w.engine.Apply(ctx, root, changes, nodes, nodes)
			if err == nil && count <= oldCount {
				if state.ChunkSize == 0 {
					if state.TotalSize != 0 {
						return nil, errors.New("plain sequence cannot have total size")
					}
					root, err = w.engine.Truncate(ctx, root, count, nodes, nodes)
				} else {
					root, err = w.engine.ResizeMeasured(ctx, root, count, state.TotalSize, nodes, nodes)
				}
			}
			if err == nil && count > oldCount {
				if state.ChunkSize > 0 {
					if count-1 > math.MaxUint64/state.ChunkSize {
						return nil, errors.New("sequence size overflow")
					}
					root, err = w.engine.ResizeMeasured(ctx, root, oldCount, oldCount*state.ChunkSize, nodes, nodes)
				} else if state.TotalSize != 0 {
					return nil, errors.New("plain sequence cannot have total size")
				}
				for i := oldCount; err == nil && i < count; i++ {
					var total *uint64
					if state.ChunkSize > 0 {
						n := state.TotalSize
						if i+1 < count {
							n = (i + 1) * state.ChunkSize
						}
						total = &n
					}
					root, _, err = w.engine.Append(ctx, root, newView.Bindings[desired[input.Coordinate{Kind: input.Index, Index: i}]].Target, total, nodes, nodes)
				}
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("update authentication state: %w", err)
	}
	candidate, err := Export(ctx, w.engine, root, state, nodes)
	if err != nil {
		return nil, err
	}
	candidate.Previous = w.candidate.Root
	// Retain only reachable vectors, so successive candidates do not accumulate
	// obsolete authentication paths indefinitely.
	retained := &vectors{nodes: make(map[string][]commitment.Cell), used: make(map[string]bool)}
	for _, node := range candidate.Nodes {
		retained.nodes[string(node.Reference)] = nodes.nodes[string(node.Reference)]
	}
	return &Writer{engine: w.engine, candidate: cloneCandidate(candidate), nodes: retained}, nil
}

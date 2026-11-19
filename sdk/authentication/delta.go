package authentication

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/dewebprotocol/malt-core/auth/coordinate"
	"github.com/dewebprotocol/malt-core/engine"
	"github.com/dewebprotocol/malt-core/maltcid"
	cid "github.com/ipfs/go-cid"
)

// Delta changes typed relations in an already verified retained ArcSet. A smaller
// Count discards indices at or above that cutoff. A larger Count requires a
// binding at Count-1. Without Count the surviving indices determine the extent.
// PayloadCID changes only the opaque root payload: nil preserves it and a
// pointer to cid.Undef removes it. This is not a stateless update witness.
type Delta struct {
	Changes    []engine.Change
	Count      *uint64
	PayloadCID *cid.Cid
}

// Apply copies only changed input and authentication paths. The base remains
// immutable and usable for concurrent branches. Export is a separate operation.
func (w *Writer) Apply(ctx context.Context, delta Delta) (*Writer, error) {
	if w == nil || w.engine == nil {
		return nil, errors.New("writer is not initialized")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	meta := w.metadata
	list := meta.Descriptor.Layout == maltcid.List
	if !list && (delta.Count != nil || delta.PayloadCID != nil) {
		return nil, errors.New("Map delta cannot carry sequence metadata")
	}
	var oldCount uint64
	if list {
		oldCount = listBindingCount(w.bindings)
	}
	truncate := list && delta.Count != nil && *delta.Count < oldCount
	if list && delta.PayloadCID != nil {
		meta.PayloadCID = *delta.PayloadCID
	}
	bindings := w.bindings
	if truncate {
		bindings = bindingBefore(bindings, bindingKey(coordinate.At(*delta.Count)))
	}
	seen := make(map[coordinate.Coordinate][]byte, len(delta.Changes))
	replacements := make([]engine.Change, 0, len(delta.Changes))
	for _, change := range delta.Changes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		view, err := w.engine.Interpret(engine.State{Descriptor: meta.Descriptor, Entries: []engine.Entry{{Label: change.Label, Target: change.After}}})
		if err != nil {
			return nil, err
		}
		c := view.Bindings[0].Coordinate
		if previous, exists := seen[c]; exists {
			if !bytes.Equal(previous, change.Label) {
				return nil, engine.ErrCoordinateCollision
			}
			return nil, errors.New("duplicate delta coordinate")
		}
		seen[c] = bytes.Clone(change.Label)
		if !change.Before.Defined() && !change.After.Defined() {
			return nil, errors.New("empty binding change")
		}
		key := bindingKey(c)
		old := bindingGet(w.bindings, key)
		if old != nil && !bytes.Equal(old.entry.Label, change.Label) {
			return nil, engine.ErrCoordinateCollision
		}
		if old == nil && change.Before.Defined() || old != nil && !old.entry.Target.Equals(change.Before) {
			return nil, errors.New("old target does not match retained state")
		}
		if list && (c.Index == math.MaxUint64 || delta.Count != nil && c.Index >= *delta.Count) {
			return nil, errors.New("List change outside representable or requested extent")
		}
		if change.After.Defined() {
			bindings = bindingSet(bindings, c, engine.Entry{Label: change.Label, Target: change.After})
		} else {
			bindings = bindingDelete(bindings, key)
		}
		if !change.Before.Equals(change.After) {
			replacements = append(replacements, change)
		}
	}
	if list && delta.Count != nil && *delta.Count > oldCount && listBindingCount(bindings) != *delta.Count {
		return nil, errors.New("extended List requires a binding at Count-1")
	}
	nodes, err := w.engine.Tree.Workspace(w.nodes)
	if err != nil {
		return nil, err
	}
	root := w.root
	if truncate {
		root, err = w.engine.Truncate(ctx, root, *delta.Count, nodes, nodes)
	}
	if err == nil {
		root, err = w.engine.Apply(ctx, root, replacements, nodes, nodes)
	}
	if err == nil && list && !meta.PayloadCID.Equals(w.metadata.PayloadCID) {
		root, err = w.engine.SetPayload(ctx, root, meta.PayloadCID, nodes, nodes)
	}
	if err != nil {
		return nil, fmt.Errorf("update authentication state: %w", err)
	}
	materialized, err := nodes.Seal(root)
	if err != nil {
		return nil, err
	}
	previous := w.root.String()
	if root.Equals(w.root) {
		previous = w.previous
	}
	return &Writer{engine: w.engine, root: root, previous: previous, metadata: meta, bindings: bindings, nodes: materialized}, nil
}

package authentication

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/dewebprotocol/malt-core/auth/coordinate"
	"github.com/dewebprotocol/malt-core/engine"
	"github.com/dewebprotocol/malt-core/maltcid"
	cid "github.com/ipfs/go-cid"
)

// Delta changes typed relations in an already verified retained ArcSet. Count
// appends/truncates a List suffix; appended positions require bindings.
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
	var oldCount uint64
	if w.bindings != nil {
		oldCount = w.bindings.size
	}
	count := oldCount
	list := meta.Descriptor.Layout == maltcid.List
	if !list && (delta.Count != nil || delta.PayloadCID != nil) {
		return nil, errors.New("Map delta cannot carry sequence metadata")
	}
	if list && delta.Count != nil {
		count = *delta.Count
	}
	if list && count > oldCount && count-oldCount > uint64(len(delta.Changes)) {
		return nil, errors.New("appended positions require complete bindings")
	}
	if list && delta.PayloadCID != nil {
		meta.PayloadCID = *delta.PayloadCID
	}
	bindings := w.bindings
	if list && count < oldCount {
		bindings = bindingBefore(bindings, bindingKey(coordinate.At(count)))
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
		if list && (!change.After.Defined() || c.Index >= count) {
			return nil, errors.New("List changes require targets within the new count; use Count to truncate")
		}
		if change.After.Defined() {
			bindings = bindingSet(bindings, c, engine.Entry{Label: change.Label, Target: change.After})
		} else {
			bindings = bindingDelete(bindings, key)
		}
		if (!list || c.Index < oldCount) && !change.Before.Equals(change.After) {
			replacements = append(replacements, change)
		}
	}
	if list {
		var size uint64
		if bindings != nil {
			size = bindings.size
		}
		if size != count {
			return nil, errors.New("List delta leaves missing positions")
		}
	}
	nodes, err := w.engine.Tree.Workspace(w.nodes)
	if err != nil {
		return nil, err
	}
	root, err := w.engine.Apply(ctx, w.root, replacements, nodes, nodes)
	if err != nil {
		return nil, err
	}
	if list && count < oldCount {
		root, err = w.engine.Truncate(ctx, root, count, nodes, nodes)
	}
	if err == nil && list && count > oldCount {
		targets := make([]cid.Cid, 0, count-oldCount)
		for i := oldCount; i < count; i++ {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			entry := bindingGet(bindings, bindingKey(coordinate.At(i)))
			if entry == nil {
				return nil, errors.New("appended position is missing")
			}
			targets = append(targets, entry.entry.Target)
		}
		if err == nil {
			root, _, err = w.engine.AppendBatch(ctx, root, targets, nodes, nodes)
		}
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

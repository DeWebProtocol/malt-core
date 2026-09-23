package authentication

import (
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/dewebprotocol/malt-core/auth/coordinate"
	"github.com/dewebprotocol/malt-core/auth/engine"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

// Delta changes typed relations in an already verified retained ArcSet. Count
// appends/truncates a Positional suffix; appended positions require bindings.
// Measured length changes require an explicit TotalSize. Chunk geometry changes
// use Update with complete state. This is not a stateless update witness.
type Delta struct {
	Changes   []engine.Change
	Count     *uint64
	TotalSize *uint64
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
	positional := meta.Descriptor.Layout == maltcid.Positional
	if !positional && (delta.Count != nil || delta.TotalSize != nil) {
		return nil, errors.New("Prefix delta cannot carry sequence metadata")
	}
	if positional && delta.Count != nil {
		count = *delta.Count
	}
	if positional && count > oldCount && count-oldCount > uint64(len(delta.Changes)) {
		return nil, errors.New("appended positions require complete bindings")
	}
	if positional {
		if meta.ChunkSize == 0 && delta.TotalSize != nil {
			return nil, errors.New("plain sequence cannot carry byte measurements")
		}
		if meta.ChunkSize > 0 && count != oldCount && delta.TotalSize == nil {
			return nil, errors.New("measured length changes require total size")
		}
		if delta.TotalSize != nil {
			meta.TotalSize = *delta.TotalSize
		}
	}
	bindings := w.bindings
	if positional && count < oldCount {
		bindings = bindingBefore(bindings, bindingKey(coordinate.At(count)))
	}
	seen := make(map[coordinate.Value]bool, len(delta.Changes))
	replacements := make([]engine.Change, 0, len(delta.Changes))
	for _, change := range delta.Changes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		view, err := w.engine.Interpret(engine.State{Descriptor: meta.Descriptor, Entries: []engine.Entry{{Input: change.Input, Target: change.After}}})
		if err != nil {
			return nil, err
		}
		c := view.Bindings[0].Coordinate
		if seen[c] {
			return nil, errors.New("duplicate delta coordinate")
		}
		seen[c] = true
		if !change.Before.Defined() && !change.After.Defined() {
			return nil, errors.New("empty binding change")
		}
		key := bindingKey(c)
		old := bindingGet(w.bindings, key)
		if old == nil && change.Before.Defined() || old != nil && !old.entry.Target.Equals(change.Before) {
			return nil, errors.New("old target does not match retained state")
		}
		if positional && (!change.After.Defined() || c.Index >= count) {
			return nil, errors.New("Positional changes require targets within the new count; use Count to truncate")
		}
		if change.After.Defined() {
			bindings = bindingSet(bindings, c, engine.Entry{Input: change.Input, Target: change.After})
		} else {
			bindings = bindingDelete(bindings, key)
		}
		if (!positional || c.Index < oldCount) && !change.Before.Equals(change.After) {
			replacements = append(replacements, change)
		}
	}
	if positional {
		var size uint64
		if bindings != nil {
			size = bindings.size
		}
		if size != count {
			return nil, errors.New("Positional delta leaves missing positions")
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
	if positional && count <= oldCount && (count != oldCount || meta.TotalSize != w.metadata.TotalSize) {
		if meta.ChunkSize == 0 {
			root, err = w.engine.Truncate(ctx, root, count, nodes, nodes)
		} else {
			root, err = w.engine.ResizeMeasured(ctx, root, count, meta.TotalSize, nodes, nodes)
		}
	}
	if err == nil && positional && count > oldCount {
		if meta.ChunkSize > 0 {
			if count-1 > math.MaxUint64/meta.ChunkSize {
				return nil, errors.New("sequence size overflow")
			}
			root, err = w.engine.ResizeMeasured(ctx, root, oldCount, oldCount*meta.ChunkSize, nodes, nodes)
		}
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
		var total *uint64
		if meta.ChunkSize > 0 {
			total = &meta.TotalSize
		}
		if err == nil {
			root, _, err = w.engine.AppendBatch(ctx, root, targets, total, nodes, nodes)
		}
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

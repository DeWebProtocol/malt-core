package authentication

import (
	"bytes"
	"context"
	"errors"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer"
	"github.com/dewebprotocol/malt-core/engine"
	cid "github.com/ipfs/go-cid"
)

// Lookup returns an original retained relation without exporting the complete
// state. It is local computation, not portable evidence of membership or absence.
func (w *Writer) Lookup(ctx context.Context, label []byte) (cid.Cid, error) {
	if w == nil || w.nodes == nil {
		return cid.Undef, errors.New("writer is not initialized")
	}
	if err := ctx.Err(); err != nil {
		return cid.Undef, err
	}
	view, err := w.engine.Interpret(engine.State{Descriptor: w.metadata.Descriptor, Entries: []engine.Entry{{Label: label}}})
	if err != nil {
		return cid.Undef, err
	}
	n := bindingGet(w.bindings, bindingKey(view.Bindings[0].Coordinate))
	if n == nil {
		return cid.Undef, nil
	}
	if !bytes.Equal(n.entry.Label, label) {
		return cid.Undef, engine.ErrCoordinateCollision
	}
	return n.entry.Target, nil
}

// Nodes creates an independent, traversal-local reader over this immutable
// Root's closed DAG. Read parents before their children, as Core tree operations
// do. The reader is not shared by concurrent operations. Returned cells are owned
// copies; neither reads nor a type assertion to NodeUpdater can change w.
func (w *Writer) Nodes() (materializer.NodeLookup, error) {
	if w == nil || w.nodes == nil {
		return nil, errors.New("writer is not initialized")
	}
	return w.engine.Tree.Workspace(w.nodes)
}

// Len is the number of retained original relations (the count for List).
func (w *Writer) Len() uint64 {
	if w == nil || w.bindings == nil {
		return 0
	}
	return w.bindings.size
}

// StateCharge reports the same conservative retained-state charge used by
// Session. It is an accounting bound, not allocator RSS. Independent writers
// may share immutable subtrees; charging each in full safely overcounts sharing.
func (w *Writer) StateCharge() uint64 {
	if w == nil || w.nodes == nil {
		return 0
	}
	return w.stateCharge()
}

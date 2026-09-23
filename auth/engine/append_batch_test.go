package engine_test

import (
	"context"
	"github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/engine"
	"github.com/dewebprotocol/malt-core/auth/input"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
	"testing"
)

func TestAppendBatchGrowsMultipleLevels(t *testing.T) {
	e, nodes := setup(t, maltcid.IPA256)
	value := target("batch")
	state := engine.State{Descriptor: maltcid.RootDescriptor{Layout: maltcid.Positional, Profile: maltcid.IPA256}, Entries: []engine.Entry{{Input: input.IndexValue(0), Target: value}}}
	root, err := e.Build(t.Context(), state, nodes)
	if err != nil {
		t.Fatal(err)
	}
	// Grow straight from height zero to height two.
	targets := make([]cid.Cid, 255*255)
	for i := range targets {
		targets[i] = value
		state.Entries = append(state.Entries, engine.Entry{Input: input.IndexValue(uint64(i + 1)), Target: value})
	}
	next, first, err := e.AppendBatch(t.Context(), root, targets, nil, nodes, nodes)
	if err != nil {
		t.Fatal(err)
	}
	if first != 1 {
		t.Fatalf("first index = %d", first)
	}
	fresh, err := e.Build(t.Context(), state, memory.NewNodes())
	if err != nil {
		t.Fatal(err)
	}
	if !next.Equals(fresh) {
		t.Fatal("multi-level growth differs from rebuild")
	}
	if err := e.ValidateState(t.Context(), next, state, nodes); err != nil {
		t.Fatal(err)
	}
}

func TestAppendBatchRejectsInvalidSuffixWithoutWrites(t *testing.T) {
	e, nodes := setup(t, maltcid.IPA256)
	state := engine.State{Descriptor: maltcid.RootDescriptor{Layout: maltcid.Positional, Profile: maltcid.IPA256}, ChunkSize: 8, TotalSize: 8, Entries: []engine.Entry{{Input: input.IndexValue(0), Target: target("before")}}}
	root, err := e.Build(t.Context(), state, nodes)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		targets []cid.Cid
		size    uint64
	}{
		{nil, 8}, {[]cid.Cid{cid.Undef}, 16}, {[]cid.Cid{target("a"), target("b")}, 16},
	} {
		out := &rejectWrites{t: t}
		if _, _, err := e.AppendBatch(t.Context(), root, tc.targets, &tc.size, nodes, out); err == nil {
			t.Fatal("invalid suffix accepted")
		}
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	size := uint64(16)
	if _, _, err := e.AppendBatch(canceled, root, []cid.Cid{target("a")}, &size, nodes, &rejectWrites{t: t}); err == nil {
		t.Fatal("canceled append succeeded")
	}
	state.TotalSize = 7
	partial, err := e.Build(t.Context(), state, nodes)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.AppendBatch(t.Context(), partial, []cid.Cid{target("a")}, &size, nodes, &rejectWrites{t: t}); err == nil {
		t.Fatal("appended after partial chunk")
	}
}

type rejectWrites struct{ t *testing.T }

func (r *rejectWrites) PutNode(context.Context, maltcid.NodeRef, []commitment.Cell) error {
	r.t.Fatal("invalid append wrote a node")
	return nil
}

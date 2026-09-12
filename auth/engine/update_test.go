package engine_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/engine"
	"github.com/dewebprotocol/malt-core/auth/input"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

type countedNodes struct {
	*memory.Nodes
	reads, writes int
}

func (n *countedNodes) GetNode(ctx context.Context, r maltcid.NodeRef) ([]commitment.Cell, error) {
	n.reads++
	return n.Nodes.GetNode(ctx, r)
}
func (n *countedNodes) PutNode(ctx context.Context, r maltcid.NodeRef, c []commitment.Cell) error {
	n.writes++
	return n.Nodes.PutNode(ctx, r, c)
}

func TestPrefixBatchCopiesPathsAndValidatesBeforeWriting(t *testing.T) {
	ctx := context.Background()
	e, base := setup(t, maltcid.IPA256)
	nodes := &countedNodes{Nodes: base}
	state := engine.State{Descriptor: maltcid.RootDescriptor{Layout: maltcid.Prefix, Profile: maltcid.IPA256}}
	for i := 0; i < 256; i++ {
		for j := 0; j < 2; j++ {
			var key [32]byte
			key[0] = byte(i)
			key[1] = byte(j)
			state.Entries = append(state.Entries, engine.Entry{Input: input.KeyValue(key), Target: target(fmt.Sprint(i, j))})
		}
	}
	root, err := e.Build(ctx, state, nodes)
	if err != nil {
		t.Fatal(err)
	}
	nodes.reads = 0
	nodes.writes = 0
	changes := []engine.Change{{Input: state.Entries[0].Input, Before: state.Entries[0].Target, After: target("new")}, {Input: state.Entries[1].Input, Before: state.Entries[1].Target}}
	next, err := e.Apply(ctx, root, changes, nodes, nodes)
	if err != nil {
		t.Fatal(err)
	}
	if nodes.reads > 2 || nodes.writes > 2 {
		t.Fatalf("update scanned unrelated nodes: %d reads %d writes", nodes.reads, nodes.writes)
	}
	state.Entries[0].Target = target("new")
	state.Entries = append(state.Entries[:1], state.Entries[2:]...)
	expected, err := e.Build(ctx, state, memory.NewNodes())
	if err != nil || !next.Equals(expected) {
		t.Fatalf("incremental root differs from fresh build: %v", err)
	}
	if err := e.ValidateState(ctx, next, state, nodes); err != nil {
		t.Fatal(err)
	}
	nodes.writes = 0
	changes[0].Before = target("wrong")
	if _, err := e.Apply(ctx, next, changes, nodes, nodes); err == nil || nodes.writes != 0 {
		t.Fatal("failed batch published vectors")
	}
}

func TestPositionalPathUpdatesMatchRebuildAndRange(t *testing.T) {
	ctx := context.Background()
	e, base := setup(t, maltcid.IPA256)
	nodes := &countedNodes{Nodes: base}
	state := engine.State{Descriptor: maltcid.RootDescriptor{Layout: maltcid.Positional, Profile: maltcid.IPA256}}
	for i := 0; i < 255; i++ {
		state.Entries = append(state.Entries, engine.Entry{Input: input.IndexValue(uint64(i)), Target: target(fmt.Sprint(i))})
	}
	root, err := e.Build(ctx, state, nodes)
	if err != nil {
		t.Fatal(err)
	}
	for i := 255; i < 258; i++ {
		nodes.reads = 0
		nodes.writes = 0
		v := target(fmt.Sprint(i))
		next, index, err := e.Append(ctx, root, v, nil, nodes, nodes)
		if err != nil || index != uint64(i) {
			t.Fatalf("append %d: %v", i, err)
		}
		if nodes.reads > 2 || nodes.writes > 2 {
			t.Fatal("append rebuilt unchanged sequence")
		}
		state.Entries = append(state.Entries, engine.Entry{Input: input.IndexValue(uint64(i)), Target: v})
		expected, err := e.Build(ctx, state, memory.NewNodes())
		if err != nil || !next.Equals(expected) {
			t.Fatalf("append rebuild %d: %v", i, err)
		}
		root = next
	}
	next, err := e.Apply(ctx, root, []engine.Change{{Input: input.IndexValue(256), Before: state.Entries[256].Target, After: target("replace")}}, nodes, nodes)
	if err != nil {
		t.Fatal(err)
	}
	state.Entries[256].Target = target("replace")
	expected, _ := e.Build(ctx, state, memory.NewNodes())
	if !next.Equals(expected) {
		t.Fatal("replace root")
	}
	root = next
	for _, count := range []uint64{256, 255, 254, 1, 0} {
		next, err := e.Truncate(ctx, root, count, nodes, nodes)
		if err != nil {
			t.Fatalf("truncate %d: %v", count, err)
		}
		state.Entries = state.Entries[:count]
		expected, err := e.Build(ctx, state, memory.NewNodes())
		if err != nil || !next.Equals(expected) {
			t.Fatalf("truncate rebuild %d: %v", count, err)
		}
		root = next
	}
	state.ChunkSize = 4
	state.TotalSize = 8
	state.Entries = []engine.Entry{{Input: input.IndexValue(0), Target: target("first")}, {Input: input.IndexValue(1), Target: target("second")}}
	root, err = e.Build(ctx, state, nodes)
	if err != nil {
		t.Fatal(err)
	}
	total := uint64(10)
	root, _, err = e.Append(ctx, root, target("last"), &total, nodes, nodes)
	if err != nil {
		t.Fatal(err)
	}
	result, err := e.ProveRange(ctx, root, 3, nil, nodes)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := e.VerifyRange(root, 3, nil, result); err != nil || !ok || len(result.Segments) != 3 {
		t.Fatalf("range %v %v", ok, err)
	}
	result.Segments[1].Target = cid.Undef
	if ok, _ := e.VerifyRange(root, 3, nil, result); ok {
		t.Fatal("tampered range verified")
	}
	if _, _, err = e.Append(ctx, root, target("invalid"), &total, nodes, nodes); err == nil {
		t.Fatal("append after partial chunk")
	}
}

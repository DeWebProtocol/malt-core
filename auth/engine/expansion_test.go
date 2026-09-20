package engine_test

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer"
	"github.com/dewebprotocol/malt-core/auth/arcset/materializer/encoded"
	"github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
	"github.com/dewebprotocol/malt-core/auth/engine"
	"github.com/dewebprotocol/malt-core/auth/input"
	listview "github.com/dewebprotocol/malt-core/auth/semantic/list"
	"github.com/dewebprotocol/malt-core/auth/semantic/list/tree"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

type rootOnlyNodes struct {
	materializer.NodeLookup
	gets int
}

func (s *rootOnlyNodes) GetNode(ctx context.Context, ref maltcid.NodeRef) ([]commitment.Cell, error) {
	s.gets++
	return s.NodeLookup.GetNode(ctx, ref)
}

func TestSnapshotRejectsHugeLogicalExpansionAtRoot(t *testing.T) {
	e, nodes := setup(t, maltcid.IPA256)
	scheme, err := ipa.NewCommitterScheme(ipa.ProfileDirect)
	if err != nil {
		t.Fatal(err)
	}
	// A root can advertise an enormous logical count with only one supplied
	// vector. Reject its count before traversing or allocating logical entries.
	cells := make([]commitment.Cell, 256)
	cells[0] = []byte{maltcid.MetadataCell}
	for _, v := range []uint64{3, 255 * 255 * 255 * 255, 0, 0} {
		cells[0] = binary.BigEndian.AppendUint64(cells[0], v)
	}
	primitive, err := scheme.Commit(cells)
	if err != nil {
		t.Fatal(err)
	}
	c, err := primitive.CommitmentBytes(maltcid.IPA256)
	if err != nil {
		t.Fatal(err)
	}
	d := maltcid.RootDescriptor{Layout: maltcid.Positional, Profile: maltcid.IPA256}
	root, err := maltcid.NewRoot(d, c)
	if err != nil {
		t.Fatal(err)
	}
	ref, _, _ := maltcid.RootNode(root)
	if err := nodes.PutNode(context.Background(), ref, cells); err != nil {
		t.Fatal(err)
	}
	counted := &rootOnlyNodes{NodeLookup: nodes}
	_, err = e.SnapshotBounded(context.Background(), root, counted, 1)
	if err == nil || !strings.Contains(err.Error(), "exceeds bound") || counted.gets != 1 {
		t.Fatalf("count bound: gets=%d err=%v", counted.gets, err)
	}
	if err = e.ValidateState(context.Background(), root, engine.State{Descriptor: d}, counted); err == nil {
		t.Fatal("tiny candidate accepted enormous logical state")
	}
}

func TestRetainNestedRootWithSharedAAIndependentNodes(t *testing.T) {
	e, _ := setup(t, maltcid.IPA256)
	store := memory.New(true)
	nodes := encoded.Nodes{Lookup: store, Updater: store, Scope: "retention"}
	ctx := context.Background()
	d := maltcid.RootDescriptor{Layout: maltcid.Prefix, InputRule: 1, Profile: maltcid.IPA256}
	value := input.LabelValue([]byte("one"))
	child, err := e.Build(ctx, engine.State{Descriptor: d, Entries: []engine.Entry{{Input: value, Target: target("payload")}}}, nodes)
	if err != nil {
		t.Fatal(err)
	}
	coordinate, _ := e.Rules.Derive(input.BytesSHA256, value)
	nativeD := d
	nativeD.InputRule = 0
	nativeChild, err := e.Build(ctx, engine.State{Descriptor: nativeD, Entries: []engine.Entry{{Input: input.KeyValue(coordinate.Key), Target: target("payload")}}}, nodes)
	if err != nil {
		t.Fatal(err)
	}
	parent, err := e.Build(ctx, engine.State{Descriptor: d, Entries: []engine.Entry{{Input: input.LabelValue([]byte("child")), Target: child}}}, nodes)
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.Build(ctx, engine.State{Descriptor: d, Entries: []engine.Entry{{Input: value, Target: target("discarded")}}}, nodes)
	if err != nil {
		t.Fatal(err)
	}
	before := store.EntryCount()
	store.RetainRoots(map[string][]cid.Cid{"retention": {parent}})
	if store.EntryCount() >= before {
		t.Fatal("unreachable node was retained")
	}
	for _, q := range []struct {
		root  cid.Cid
		input input.Value
	}{{child, value}, {nativeChild, input.KeyValue(coordinate.Key)}} {
		result, err := e.Prove(ctx, q.root, q.input, nodes)
		if err != nil {
			t.Fatal(err)
		}
		if ok, err := e.Verify(q.root, q.input, result); err != nil || !ok {
			t.Fatal("retained shared node", err)
		}
	}
}

func TestRetainListPointingToV0Child(t *testing.T) {
	e, _ := setup(t, maltcid.IPA256)
	store := memory.New(true)
	nodes := encoded.Nodes{Lookup: store, Updater: store, Scope: "mixed"}
	value := input.LabelValue([]byte("child-label"))
	d := maltcid.RootDescriptor{Layout: maltcid.Prefix, InputRule: 1, Profile: maltcid.IPA256}
	child, err := e.Build(t.Context(), engine.State{Descriptor: d, Entries: []engine.Entry{{Input: value, Target: target("payload")}}}, nodes)
	if err != nil {
		t.Fatal(err)
	}
	scheme, err := ipa.NewCommitterScheme(ipa.ProfileDirect)
	if err != nil {
		t.Fatal(err)
	}
	list, err := tree.NewList(scheme, store)
	if err != nil {
		t.Fatal(err)
	}
	parent, err := list.Commit(t.Context(), "mixed", listview.NewViewFromSlice([]cid.Cid{child}))
	if err != nil {
		t.Fatal(err)
	}
	store.RetainRoots(map[string][]cid.Cid{"mixed": {parent}})
	result, err := e.Prove(t.Context(), child, value, nodes)
	if err != nil {
		t.Fatal("historical parent lost new child", err)
	}
	if ok, err := e.Verify(child, value, result); err != nil || !ok {
		t.Fatal("child proof", err)
	}
}

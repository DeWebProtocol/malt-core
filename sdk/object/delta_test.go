package object_test

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
	"github.com/dewebprotocol/malt-core/auth/coordinate"
	"github.com/dewebprotocol/malt-core/engine"
	"github.com/dewebprotocol/malt-core/maltcid"
	"github.com/dewebprotocol/malt-core/sdk/authentication"
	"github.com/dewebprotocol/malt-core/sdk/authentication/builtin"
	"github.com/dewebprotocol/malt-core/sdk/object"
	"github.com/dewebprotocol/malt-core/traversal"
	cid "github.com/ipfs/go-cid"
)

type deltaSource interface {
	Delta(context.Context) (object.Delta, error)
}

func deltaFor(t *testing.T, o deltaSource) object.Delta {
	t.Helper()
	d, err := o.Delta(context.Background())
	must(t, err)
	return d
}

func applyCollected(t *testing.T, d object.Delta, nodes *memory.Nodes, states map[string]engine.State) {
	t.Helper()
	for _, change := range d.ArcSets {
		candidate, err := change.Export(context.Background())
		must(t, err)
		if candidate.Root != change.After.String() {
			t.Fatal("candidate root does not match delta")
		}
		bindings := map[string]cid.Cid{}
		if change.Before.Defined() {
			base, ok := states[change.Before.KeyString()]
			if !ok || candidate.Previous != change.Before.String() {
				t.Fatal("missing delta baseline or mismatched candidate Previous")
			}
			for _, e := range base.Entries {
				bindings[string(e.Label)] = e.Target
			}
		} else if candidate.Previous != "" {
			t.Fatal("new vertex inherited a different graph's lineage")
		}
		for _, arc := range change.Changes {
			if !bindings[string(arc.Label)].Equals(arc.Before) {
				t.Fatalf("wrong previous target for %x", arc.Label)
			}
			if arc.After.Defined() {
				bindings[string(arc.Label)] = arc.After
			} else {
				delete(bindings, string(arc.Label))
			}
		}
		if len(bindings) != len(candidate.State.Entries) {
			t.Fatal("delta does not reconstruct the new ArcSet")
		}
		for _, e := range candidate.State.Entries {
			if !bindings[string(e.Label)].Equals(e.Target) {
				t.Fatalf("delta reconstruction mismatch for %x", e.Label)
			}
		}
		must(t, authentication.Materialize(context.Background(), engineFor(t), candidate, nodes))
		states[change.After.KeyString()] = candidate.State
	}
	for _, b := range d.Blocks {
		actual, err := b.CID.Prefix().Sum(b.Bytes)
		must(t, err)
		if !actual.Equals(b.CID) {
			t.Fatal("collected bytes do not match their CID")
		}
	}
}

func TestCollectedDeltasReconstructAndProveMixedGraph(t *testing.T) {
	parent := mapFor(t)
	l, err := object.NewList(engineFor(t), object.ListConfig(maltcid.KZG4096))
	must(t, err)
	one, two := leaf(t, "one"), leaf(t, "two")
	must(t, l.Append(one, two))
	must(t, parent.Set([]byte("items"), l))
	first := commit(t, parent)
	d := deltaFor(t, parent)
	if d.Before.Defined() || !d.After.Equals(first) || len(d.ArcSets) != 2 || len(d.Blocks) != 2 || len(d.External) != 0 {
		t.Fatalf("unexpected initial delta: %+v", d)
	}
	if !d.ArcSets[0].After.Equals(l.CID()) || !d.ArcSets[1].After.Equals(parent.CID()) {
		t.Fatal("parent precedes child")
	}
	nodes, states := memory.NewNodes(), map[string]engine.State{}
	applyCollected(t, d, nodes, states)
	initial := d // Retained exports must survive subsequent successful Commits.
	oldList := l.CID()
	three := leaf(t, "three")
	must(t, l.Set(0, three))
	must(t, l.Remove(1))
	second := commit(t, parent)
	d = deltaFor(t, parent)
	if !d.Before.Equals(first) || !d.After.Equals(second) || len(d.ArcSets) != 2 || len(d.Blocks) != 1 || !d.Blocks[0].CID.Equals(three.Payload()) {
		t.Fatalf("unexpected update delta: %+v", d)
	}
	if !d.ArcSets[0].Before.Equals(oldList) || len(d.ArcSets[0].Changes) != 2 {
		t.Fatal("List replacement/truncation delta is incomplete")
	}
	applyCollected(t, d, nodes, states)
	applyCollected(t, initial, memory.NewNodes(), map[string]engine.State{})
	verifier, err := builtin.NewVerifier()
	must(t, err)
	steps := [][]byte{[]byte("items"), coordinate.EncodeIndex(0)}
	for _, test := range []struct{ root, target cid.Cid }{{first, one.Payload()}, {second, three.Payload()}} {
		target, proof, err := traversal.ResolvePath(context.Background(), engineFor(t), test.root, steps, nodes)
		must(t, err)
		ok, err := traversal.Verify(verifier, test.root, steps, target, proof)
		must(t, err)
		if !ok || !target.Equals(test.target) {
			t.Fatal("delta materialization does not reproduce a verifiable version")
		}
	}
	commit(t, parent)
	d = deltaFor(t, parent)
	if !d.Before.Equals(second) || !d.After.Equals(second) || len(d.ArcSets)+len(d.Blocks)+len(d.External) != 0 {
		t.Fatal("no-op emitted changes")
	}
}

func TestParentDeltaKeepsItsOwnBaselineAcrossChildCommits(t *testing.T) {
	parent, child := mapFor(t), mapFor(t)
	a, b, c := leaf(t, "a"), leaf(t, "b"), leaf(t, "c")
	must(t, child.Set([]byte("body"), a))
	must(t, parent.Set([]byte("doc"), child))
	oldRoot := commit(t, parent)
	oldChild := child.CID()
	must(t, child.Set([]byte("body"), b))
	commit(t, child)
	must(t, child.Set([]byte("body"), c))
	commit(t, child)
	commit(t, parent)
	d := deltaFor(t, parent)
	if !d.Before.Equals(oldRoot) || len(d.ArcSets) != 2 || len(d.Blocks) != 1 || !d.Blocks[0].CID.Equals(c.Payload()) {
		t.Fatal("child Commit advanced the parent's baseline")
	}
	arc := d.ArcSets[0]
	if !arc.Before.Equals(oldChild) || len(arc.Changes) != 1 || !arc.Changes[0].Before.Equals(a.Payload()) || !arc.Changes[0].After.Equals(c.Payload()) {
		t.Fatalf("wrong original child baseline: %+v", arc)
	}
	exported, err := arc.Export(context.Background())
	must(t, err)
	if exported.Previous != oldChild.String() {
		t.Fatal("candidate inherited an intermediate child's lineage")
	}

	// A newly attached, previously committed subtree must export its full state
	// and bytes relative to this parent's graph, not its own prior Commit.
	other := mapFor(t)
	must(t, other.Set([]byte("new"), child))
	commit(t, other)
	d = deltaFor(t, other)
	if len(d.ArcSets) != 2 || d.ArcSets[0].Before.Defined() || len(d.Blocks) != 1 {
		t.Fatal("attached subtree was treated as already present in the new parent")
	}
	exported, err = d.ArcSets[0].Export(context.Background())
	must(t, err)
	if exported.Previous != "" {
		t.Fatal("new parent's initial candidate has an unavailable previous root")
	}
}

func TestDeltaDeduplicatesContentsAndOwnsReturnedBuffers(t *testing.T) {
	m, child := mapFor(t), mapFor(t)
	one, duplicate := leaf(t, "same bytes"), leaf(t, "same bytes")
	must(t, child.Set([]byte("a"), one))
	must(t, child.Set([]byte("b"), duplicate))
	must(t, m.Set([]byte("a"), child))
	must(t, m.Set([]byte("b"), child))
	commit(t, m)
	d := deltaFor(t, m)
	if len(d.ArcSets) != 2 || len(d.Blocks) != 1 {
		t.Fatal("shared roots or equal block CIDs were duplicated")
	}
	d.Blocks[0].Bytes[0] ^= 0xff
	d.ArcSets[0].Changes[0].Label[0] ^= 0xff
	fresh := deltaFor(t, m)
	if !bytes.Equal(fresh.Blocks[0].Bytes, one.Bytes()) || bytes.Equal(fresh.ArcSets[0].Changes[0].Label, d.ArcSets[0].Changes[0].Label) {
		t.Fatal("delta buffers alias snapshots")
	}

	// Renaming a reference and deleting a second reference change only arcs.
	m.Delete([]byte("b"))
	m.Delete([]byte("a"))
	must(t, m.Set([]byte("renamed"), child))
	commit(t, m)
	d = deltaFor(t, m)
	if len(d.ArcSets) != 1 || len(d.ArcSets[0].Changes) != 3 || len(d.Blocks) != 0 || len(d.External) != 0 {
		t.Fatal("rename/alias removal duplicated immutable content")
	}
	m.Delete([]byte("renamed"))
	commit(t, m)
	d = deltaFor(t, m)
	if len(d.ArcSets) != 1 || len(d.ArcSets[0].Changes) != 1 || d.ArcSets[0].Changes[0].After.Defined() || len(d.Blocks) != 0 {
		t.Fatal("removal was not a relation-only delta")
	}
}

type externalObject struct{ target cid.Cid }

func (o *externalObject) Payload() cid.Cid { return o.target }
func (o *externalObject) Config() object.CommitConfig {
	return object.CommitConfig{Content: o.target.Prefix()}
}
func (o *externalObject) Commit(context.Context) (cid.Cid, error) { return o.target, nil }

func TestDeltaIdentifiesExternalCIDDependencies(t *testing.T) {
	m := mapFor(t)
	known, unknown := leaf(t, "known"), leaf(t, "unknown")
	m.SetPayload(unknown.Payload())
	must(t, m.Set([]byte("opaque-known"), &externalObject{target: known.Payload()}))
	must(t, m.Set([]byte("known-bytes"), known))
	must(t, m.Set([]byte("opaque-unknown"), &externalObject{target: unknown.Payload()}))
	commit(t, m)
	d := deltaFor(t, m)
	if len(d.Blocks) != 1 || !d.Blocks[0].CID.Equals(known.Payload()) || len(d.External) != 1 || !d.External[0].Equals(unknown.Payload()) {
		t.Fatalf("incorrect external dependencies: %+v", d)
	}
	// The same CID as a payload dependency cannot put its new parent before it.
	parent, nested := mapFor(t), mapFor(t)
	root := commit(t, nested)
	parent.SetPayload(root)
	must(t, m.Set([]byte("a-parent"), parent))
	must(t, m.Set([]byte("z-nested"), nested))
	commit(t, m)
	d = deltaFor(t, m)
	positions := map[string]int{}
	for i, arc := range d.ArcSets {
		positions[arc.After.KeyString()] = i
	}
	if positions[nested.CID().KeyString()] >= positions[parent.CID().KeyString()] {
		t.Fatal("CID-only dependency was emitted after its parent")
	}
}

type countingScheme struct {
	*ipa.Scheme
	commits, replacements int
	fail                  error
	onWrite               func()
}

func (s *countingScheme) Commit(cells []commitment.Cell) (commitment.Value, error) {
	s.commits++
	if s.onWrite != nil {
		s.onWrite()
	}
	if s.fail != nil {
		return commitment.Value{}, s.fail
	}
	return s.Scheme.Commit(cells)
}
func (s *countingScheme) Replace(cells []commitment.Cell, index uint64, before, after commitment.Cell) (commitment.Value, error) {
	s.replacements++
	if s.onWrite != nil {
		s.onWrite()
	}
	if s.fail != nil {
		return commitment.Value{}, s.fail
	}
	return s.Scheme.Replace(cells, index, before, after)
}
func countedEngine(t *testing.T) (*engine.Engine, *countingScheme) {
	t.Helper()
	s, err := ipa.NewCommitterScheme(ipa.ProfileDirect)
	must(t, err)
	counted := &countingScheme{Scheme: s}
	profiles := engine.NewRegistry()
	must(t, profiles.Register(counted))
	return engine.New(profiles), counted
}

func TestObjectReusesWriterForNoOpAndUpdates(t *testing.T) {
	e, counted := countedEngine(t)
	l, err := object.NewList(e, object.ListConfig(maltcid.IPA256))
	must(t, err)
	first, next := leaf(t, "first"), leaf(t, "next")
	for i := 0; i < 256; i++ {
		must(t, l.Append(first))
	}
	commit(t, l)
	full := counted.commits
	counted.commits, counted.replacements = 0, 0
	commit(t, l)
	if counted.commits != 0 || counted.replacements != 0 {
		t.Fatal("no-op recomputed commitments")
	}
	must(t, l.Set(0, next))
	commit(t, l)
	if work := counted.commits + counted.replacements; work == 0 || work >= full {
		t.Fatalf("incremental commitment work = %d, full build = %d", work, full)
	}
	checkBinding(t, retained(t, l), coordinate.EncodeIndex(0), next.Payload())
}

func TestFailedRootCommitDoesNotAdvanceAnySnapshots(t *testing.T) {
	e, backend := countedEngine(t)
	root, err := object.NewMap(e, object.MapConfig(maltcid.IPA256))
	must(t, err)
	child := mapFor(t)
	one, two := leaf(t, "old"), leaf(t, "new")
	must(t, child.Set([]byte("body"), one))
	must(t, root.Set([]byte("child"), child))
	oldRoot := commit(t, root)
	oldChild, oldWriter := child.CID(), retained(t, child)
	previousDelta := deltaFor(t, root)
	must(t, child.Set([]byte("body"), two))
	backend.onWrite = func() {
		if !child.CID().Equals(oldChild) || retained(t, child) != oldWriter {
			t.Fatal("child snapshot became visible before parent succeeded")
		}
	}
	failed := errors.New("parent commitment failed")
	backend.fail = failed
	if _, err := root.Commit(context.Background()); !errors.Is(err, failed) {
		t.Fatalf("parent failure: %v", err)
	}
	if !root.CID().Equals(oldRoot) || !child.CID().Equals(oldChild) || retained(t, child) != oldWriter {
		t.Fatal("failed parent changed committed snapshots")
	}
	if _, err := two.Delta(context.Background()); !errors.Is(err, object.ErrNotCommitted) {
		t.Fatal("failed graph advanced the new immutable leaf")
	}
	if !reflect.DeepEqual(previousDelta, deltaFor(t, root)) {
		t.Fatal("failed Commit replaced the previous delta")
	}
	backend.fail = nil
	backend.onWrite = nil
	commit(t, root)
	d := deltaFor(t, root)
	if len(d.ArcSets) != 2 || !d.ArcSets[0].Before.Equals(oldChild) || !d.Before.Equals(oldRoot) || len(d.Blocks) != 1 {
		t.Fatal("retry lost the original baseline or new block")
	}
}

type callbackObject struct {
	object.Object
	callback func() error
}

func (o *callbackObject) Commit(ctx context.Context) (cid.Cid, error) {
	root, err := o.Object.Commit(ctx)
	if err != nil {
		return cid.Undef, err
	}
	return root, o.callback()
}

func TestCancelOrChildErrorDiscardsEarlierStagedVertices(t *testing.T) {
	for _, cancelCommit := range []bool{false, true} {
		root, child := mapFor(t), mapFor(t)
		one, two := leaf(t, "one"), leaf(t, "two")
		must(t, child.Set([]byte("body"), one))
		must(t, root.Set([]byte("a-child"), child))
		oldRoot := commit(t, root)
		oldChild := child.CID()
		must(t, child.Set([]byte("body"), two))
		ctx, cancel := context.WithCancel(context.Background())
		failed := errors.New("later child failed")
		last := &callbackObject{Object: leaf(t, "last"), callback: func() error {
			if cancelCommit {
				cancel()
				return nil
			}
			return failed
		}}
		must(t, root.Set([]byte("z-last"), last))
		_, err := root.Commit(ctx)
		cancel()
		if err == nil || !root.CID().Equals(oldRoot) || !child.CID().Equals(oldChild) {
			t.Fatalf("error/cancellation advanced state: %v", err)
		}
		if _, err := two.Delta(context.Background()); !errors.Is(err, object.ErrNotCommitted) {
			t.Fatal("canceled traversal committed content")
		}
		root.Delete([]byte("z-last"))
		commit(t, root)
		if d := deltaFor(t, root); len(d.Blocks) != 1 || !d.Before.Equals(oldRoot) {
			t.Fatal("retry lost changes")
		}
	}
}

func TestConfigurationOnlyChangeStillEmitsArcSet(t *testing.T) {
	b, err := object.NewBase(engineFor(t), object.MapConfig(maltcid.IPA256))
	must(t, err)
	o := &tagged{Base: b, Child: leaf(t, "body"), config: object.MapConfig(maltcid.IPA256)}
	before := commit(t, o)
	o.config = object.MapConfig(maltcid.KZG4096)
	after := commit(t, o)
	d := deltaFor(t, o)
	if before.Equals(after) || len(d.ArcSets) != 1 || len(d.ArcSets[0].Changes) != 0 || len(d.Blocks) != 0 {
		t.Fatal("configuration-only change was dropped or rewrote blocks")
	}
	checkBinding(t, retained(t, o), []byte("child"), o.Child.Payload())
}

func TestImmutableDeltaAndCanceledReads(t *testing.T) {
	o := leaf(t, "")
	if _, err := o.Delta(context.Background()); !errors.Is(err, object.ErrNotCommitted) {
		t.Fatal("uncommitted block has a delta")
	}
	commit(t, o)
	d := deltaFor(t, o)
	if d.Before.Defined() || len(d.Blocks) != 1 || len(d.Blocks[0].Bytes) != 0 || len(d.ArcSets) != 0 {
		t.Fatal("empty immutable block was omitted")
	}
	commit(t, o)
	if d := deltaFor(t, o); len(d.Blocks) != 0 || !d.Before.Equals(d.After) {
		t.Fatal("immutable block was emitted twice")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := o.Delta(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled delta: %v", err)
	}
}

func TestSharedBaseAndCopiedContainersCannotMergeHistory(t *testing.T) {
	b, err := object.NewBase(engineFor(t), object.MapConfig(maltcid.IPA256))
	must(t, err)
	first := &tagged{Base: b, Child: leaf(t, "one"), config: object.MapConfig(maltcid.IPA256)}
	second := &tagged{Base: b, Child: leaf(t, "two"), config: object.MapConfig(maltcid.IPA256)}
	root := mapFor(t)
	must(t, root.Set([]byte("first"), first))
	must(t, root.Set([]byte("second"), second))
	if _, err := root.Commit(context.Background()); err == nil || b.CID().Defined() || root.CID().Defined() {
		t.Fatal("Objects sharing a Base merged their histories")
	}
	root.Delete([]byte("second"))
	commit(t, root)

	l, err := object.NewList(engineFor(t), object.ListConfig(maltcid.IPA256))
	must(t, err)
	copied := *l
	must(t, root.Set([]byte("list"), l))
	must(t, root.Set([]byte("copied"), &copied))
	before := root.CID()
	if _, err := root.Commit(context.Background()); err == nil || !root.CID().Equals(before) || l.CID().Defined() || copied.CID().Defined() {
		t.Fatal("copied mutable List merged vertex identities")
	}
}

func TestPayloadChangeAppearsAsBindingAndExternalDependency(t *testing.T) {
	m := mapFor(t)
	first, second := leaf(t, "payload one"), leaf(t, "payload two")
	m.SetPayload(first.Payload())
	commit(t, m)
	m.SetPayload(second.Payload())
	commit(t, m)
	d := deltaFor(t, m)
	if len(d.ArcSets) != 1 || len(d.ArcSets[0].Changes) != 1 || len(d.External) != 1 || len(d.Blocks) != 0 {
		t.Fatalf("payload change was not collected: %+v", d)
	}
	arc := d.ArcSets[0].Changes[0]
	if string(arc.Label) != "@payload" || !arc.Before.Equals(first.Payload()) || !arc.After.Equals(second.Payload()) || !d.External[0].Equals(second.Payload()) {
		t.Fatal("payload binding or external dependency mismatch")
	}
	m.SetPayload(cid.Undef)
	commit(t, m)
	d = deltaFor(t, m)
	if len(d.ArcSets) != 1 || len(d.ArcSets[0].Changes) != 1 || d.ArcSets[0].Changes[0].After.Defined() || len(d.External)+len(d.Blocks) != 0 {
		t.Fatal("payload removal did not produce only a binding deletion")
	}
}

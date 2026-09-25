package object_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
	"github.com/dewebprotocol/malt-core/auth/commitment/kzg"
	"github.com/dewebprotocol/malt-core/auth/coordinate"
	"github.com/dewebprotocol/malt-core/derivation"
	"github.com/dewebprotocol/malt-core/engine"
	"github.com/dewebprotocol/malt-core/maltcid"
	"github.com/dewebprotocol/malt-core/sdk/authentication"
	"github.com/dewebprotocol/malt-core/sdk/authentication/builtin"
	"github.com/dewebprotocol/malt-core/sdk/object"
	cid "github.com/ipfs/go-cid"
)

var testEngine = sync.OnceValues(func() (*engine.Engine, error) {
	profiles := engine.NewRegistry()
	i, err := ipa.NewCommitterScheme(ipa.ProfileDirect)
	if err != nil {
		return nil, err
	}
	k, err := kzg.NewScheme()
	if err != nil {
		return nil, err
	}
	if err := profiles.Register(i); err != nil {
		return nil, err
	}
	if err := profiles.Register(k); err != nil {
		return nil, err
	}
	return engine.New(profiles), nil
})

func engineFor(t *testing.T) *engine.Engine {
	t.Helper()
	e, err := testEngine()
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func leaf(t *testing.T, data string) *object.Immutable {
	t.Helper()
	o, err := object.NewImmutable([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func mapFor(t *testing.T) *object.Map {
	t.Helper()
	m, err := object.NewMap(engineFor(t), object.MapConfig(maltcid.IPA256))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func commit(t *testing.T, o object.Object) cid.Cid {
	t.Helper()
	root, err := o.Commit(context.Background())
	must(t, err)
	if !root.Defined() {
		t.Fatal("undefined root")
	}
	return root
}

func retained(t *testing.T, o interface {
	Writer() (*authentication.Writer, error)
}) *authentication.Writer {
	t.Helper()
	w, err := o.Writer()
	must(t, err)
	return w
}

func materialize(t *testing.T, writers ...*authentication.Writer) *memory.Nodes {
	t.Helper()
	nodes := memory.NewNodes()
	for _, w := range writers {
		c, err := w.Export(context.Background())
		must(t, err)
		must(t, authentication.Materialize(context.Background(), engineFor(t), c, nodes))
	}
	return nodes
}

func checkBinding(t *testing.T, w *authentication.Writer, label []byte, target cid.Cid) {
	t.Helper()
	ctx := context.Background()
	r, err := engineFor(t).Prove(ctx, w.Root(), label, materialize(t, w))
	must(t, err)
	verifier, err := builtin.NewVerifier(maltcid.IPA256, maltcid.KZG4096)
	must(t, err)
	ok, err := verifier.Verify(w.Root(), label, r)
	must(t, err)
	if !ok || r.Present != target.Defined() || !r.Target.Equals(target) {
		t.Fatalf("binding %x: verified=%v, present=%v, target=%v, want %v", label, ok, r.Present, r.Target, target)
	}
}

func TestImmutableOwnsBytesAndUsesOrdinaryCID(t *testing.T) {
	data := []byte("hello")
	o, err := object.NewImmutable(data)
	must(t, err)
	data[0] = '!'
	exported := o.Bytes()
	exported[0] = '?'
	root := commit(t, o)
	expected, err := o.Config().Content.Sum([]byte("hello"))
	must(t, err)
	if !root.Equals(expected) || !o.Payload().Equals(root) || !bytes.Equal(o.Bytes(), []byte("hello")) {
		t.Fatal("immutable content changed or CID differs from the configured raw block hash")
	}
	if _, _, err := maltcid.ParseRoot(root); err == nil {
		t.Fatal("ordinary block was parsed as a MALT Root")
	}
	if !leaf(t, "").Payload().Defined() {
		t.Fatal("empty bytes were confused with absent payload")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := o.Commit(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Commit: %v", err)
	}
}

func TestMapRecommitsLiveChildrenAndRetainsPreviousWriter(t *testing.T) {
	child, parent := mapFor(t), mapFor(t)
	first, second := leaf(t, "first"), leaf(t, "second")
	must(t, child.Set([]byte("value"), first))
	must(t, parent.Set([]byte("child"), child))
	oldRoot := commit(t, parent)
	oldParent, oldChild := retained(t, parent), retained(t, child)
	if !commit(t, parent).Equals(oldRoot) {
		t.Fatal("unchanged graph has a different Root")
	}
	must(t, child.Set([]byte("value"), second))
	if !parent.CID().Equals(oldRoot) {
		t.Fatal("CID must describe the last Commit until Commit is called again")
	}
	newRoot := commit(t, parent)
	if newRoot.Equals(oldRoot) {
		t.Fatal("parent reused a stale CID after a nested reference changed")
	}
	checkBinding(t, oldParent, []byte("child"), oldChild.Root())
	checkBinding(t, oldChild, []byte("value"), first.Payload())
	checkBinding(t, retained(t, parent), []byte("child"), child.CID())
	checkBinding(t, retained(t, child), []byte("value"), second.Payload())
}

func TestMapLabelsPayloadAndDeterminism(t *testing.T) {
	for _, profile := range []maltcid.ProfileID{maltcid.IPA256, maltcid.KZG4096} {
		t.Run(fmt.Sprint(profile), func(t *testing.T) {
			config := object.MapConfig(profile)
			m, err := object.NewMap(engineFor(t), config)
			must(t, err)
			n, err := object.NewMap(engineFor(t), config)
			must(t, err)
			one, two := leaf(t, "one"), leaf(t, "two")
			label := []byte{0xff, 0, '/'}
			must(t, m.Set(label, one))
			label[0] = 0
			must(t, m.Set([]byte{}, two))
			must(t, n.Set([]byte{}, two))
			must(t, n.Set([]byte{0xff, 0, '/'}, one))
			if !commit(t, m).Equals(commit(t, n)) {
				t.Fatal("Map depends on insertion order or a borrowed label")
			}
			if got, ok := m.Get([]byte{0xff, 0, '/'}); !ok || got != one {
				t.Fatal("binary label was not retained")
			}
			if _, ok := m.Get(nil); ok || m.Delete(nil) {
				t.Fatal("nil label aliased an empty label")
			}
			if !m.Delete([]byte{}) || m.Delete([]byte{}) || m.Len() != 1 {
				t.Fatal("Delete or Len")
			}
			m.SetPayload(two.Payload())
			payloadLabel, err := object.PayloadLabel(config)
			must(t, err)
			if err := m.Set(payloadLabel, one); err == nil {
				t.Fatal("payload binding could be overwritten through Set")
			}
			commit(t, m)
			checkBinding(t, retained(t, m), payloadLabel, two.Payload())
			m.SetPayload(cid.Undef)
			commit(t, m)
			checkBinding(t, retained(t, m), payloadLabel, cid.Undef)
		})
	}
	config := object.MapConfig(maltcid.IPA256)
	config.Authentication.DerivationProfile = uint8(derivation.Direct)
	m, err := object.NewMap(engineFor(t), config)
	must(t, err)
	key := coordinate.EncodeKey([32]byte{1})
	must(t, m.Set(key, leaf(t, "key")))
	if err := m.Set(coordinate.EncodeIndex(0), leaf(t, "wrong coordinate")); err == nil {
		t.Fatal("Map accepted an index coordinate")
	}
	label, err := object.PayloadLabel(config)
	must(t, err)
	if len(label) != 32 {
		t.Fatal("Direct payload label is not a canonical key")
	}
	payload := leaf(t, "direct payload").Payload()
	m.SetPayload(payload)
	commit(t, m)
	checkBinding(t, retained(t, m), label, payload)
}

type tagged struct {
	*object.Base
	Child          object.Object `malt:"child"`
	Optional       *object.Map   `malt:"optional,omitempty"`
	Ignored        object.Object `malt:"-"`
	UnexportedData string
	payload        cid.Cid
	config         object.CommitConfig
}

func (o *tagged) Commit(ctx context.Context) (cid.Cid, error) { return o.CommitTagged(ctx, o) }
func (o *tagged) Payload() cid.Cid                            { return o.payload }
func (o *tagged) Config() object.CommitConfig                 { return o.config }

func TestTaggedStructReadsOuterFieldsAndOverrides(t *testing.T) {
	b, err := object.NewBase(engineFor(t), object.MapConfig(maltcid.IPA256))
	must(t, err)
	one, two := leaf(t, "one"), leaf(t, "two")
	o := &tagged{Base: b, Child: one, Ignored: two, config: object.MapConfig(maltcid.KZG4096), payload: two.Payload()}
	root := commit(t, o)
	d, _, err := maltcid.ParseRoot(root)
	must(t, err)
	if d.Profile != maltcid.KZG4096 {
		t.Fatal("Base ignored the outer object's Config override")
	}
	candidate, err := retained(t, o).Export(context.Background())
	must(t, err)
	if len(candidate.State.Entries) != 2 {
		t.Fatal("untagged, ignored or omitted fields leaked into bindings")
	}
	checkBinding(t, retained(t, o), []byte("child"), one.Payload())
	checkBinding(t, retained(t, o), []byte("@payload"), two.Payload())
	o.Child = two
	if commit(t, o).Equals(root) {
		t.Fatal("recommit ignored a changed struct field")
	}
	o.Child = o
	if _, err := o.Commit(context.Background()); !errors.Is(err, object.ErrCycle) {
		t.Fatalf("tagged self-cycle: %v", err)
	}
}

type customLeaf struct {
	object.Object
	calls     int
	err       error
	undefined bool
}

func (o *customLeaf) Commit(ctx context.Context) (cid.Cid, error) {
	o.calls++
	if o.err != nil || o.undefined {
		return cid.Undef, o.err
	}
	return o.Object.Commit(ctx)
}

func TestCommitFailuresCyclesAndSharedChildren(t *testing.T) {
	m := mapFor(t)
	if _, err := m.Writer(); !errors.Is(err, object.ErrNotCommitted) || m.CID().Defined() {
		t.Fatal("uncommitted object has retained state")
	}
	shared := &customLeaf{Object: leaf(t, "shared")}
	must(t, m.Set([]byte("a"), shared))
	must(t, m.Set([]byte("b"), shared))
	root := commit(t, m)
	if shared.calls != 1 {
		t.Fatal("shared child committed more than once in a traversal")
	}
	commit(t, m)
	if shared.calls != 2 {
		t.Fatal("earlier traversal cache hid a new child Commit")
	}
	w := retained(t, m)
	failed := errors.New("child failed")
	shared.err = failed
	if _, err := m.Commit(context.Background()); !errors.Is(err, failed) {
		t.Fatalf("child failure not returned: %v", err)
	}
	if !m.CID().Equals(root) || retained(t, m) != w {
		t.Fatal("failed Commit replaced the last successful writer")
	}
	shared.err = nil
	shared.undefined = true
	if _, err := m.Commit(context.Background()); err == nil {
		t.Fatal("accepted undefined child CID")
	}
	shared.undefined = false
	must(t, m.Set([]byte("self"), m))
	if _, err := m.Commit(context.Background()); !errors.Is(err, object.ErrCycle) {
		t.Fatalf("self cycle: %v", err)
	}
	m.Delete([]byte("self"))
	if !commit(t, m).Equals(root) {
		t.Fatal("failed traversal polluted a later retry")
	}
	other := mapFor(t)
	must(t, m.Set([]byte("other"), other))
	must(t, other.Set([]byte("back"), m))
	if _, err := m.Commit(context.Background()); !errors.Is(err, object.ErrCycle) {
		t.Fatalf("two-vertex cycle: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.Commit(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
	var nilChild *object.Map
	if m.Set([]byte("nil"), nilChild) == nil || m.Set(nil, shared) == nil {
		t.Fatal("accepted nil child or label")
	}
}

func TestInvalidObjectConfigurations(t *testing.T) {
	if _, err := object.NewMap(nil, object.MapConfig(maltcid.IPA256)); err == nil {
		t.Fatal("nil engine accepted")
	}
	if _, err := object.NewMap(engineFor(t), object.ListConfig(maltcid.IPA256)); err == nil {
		t.Fatal("Map accepted Positional")
	}
	config := object.MapConfig(maltcid.IPA256)
	config.Content = leaf(t, "block").Config().Content
	if _, err := object.NewMap(engineFor(t), config); err == nil {
		t.Fatal("mixed commitment configuration accepted")
	}
	verifier, err := builtin.NewVerifier(maltcid.IPA256)
	must(t, err)
	m, err := object.NewMap(verifier, object.MapConfig(maltcid.IPA256))
	must(t, err)
	if _, err := m.Commit(context.Background()); err == nil || m.CID().Defined() {
		t.Fatal("verification-only backend committed an object")
	}
}

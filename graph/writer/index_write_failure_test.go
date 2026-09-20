package writer

import (
	"context"
	"errors"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	materializer "github.com/dewebprotocol/malt-core/auth/arcset/materializer"
	materialmemory "github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment/kzg"
	"github.com/dewebprotocol/malt-core/auth/semantic/mapping/radix"
	coremutation "github.com/dewebprotocol/malt-core/mutation"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

// failingMaterializer wraps a Materializer and fails Update calls while the fail flag
// is set. It is the test seam for the cross-layer atomicity gap: the semantic
// layer commits a valid newRoot, but the materialization write fails.
//
// The semantic runtime persists node slots with an undefined newRoot. Fail
// only writes with a defined newRoot to inject the error after semantic commit.
type failingMaterializer struct {
	inner materializer.Store
	fail  bool
	calls int
}

func (f *failingMaterializer) Get(ctx context.Context, namespace string, root cid.Cid, path arcset.Path) (cid.Cid, error) {
	return f.inner.Get(ctx, namespace, root, path)
}

func (f *failingMaterializer) BatchGet(ctx context.Context, namespace string, root cid.Cid, paths []arcset.Path) (map[arcset.Path]cid.Cid, error) {
	return f.inner.BatchGet(ctx, namespace, root, paths)
}

func (f *failingMaterializer) Update(ctx context.Context, namespace string, newRoot, oldRoot cid.Cid, arcs arcset.ArcSet) error {
	f.calls++
	// Only fail the logical root-publishing write. The semantic runtime's
	// node-slot persistence (newRoot == cid.Undef) must succeed so that the
	// semantic layer can produce a valid newRoot in the first place.
	if f.fail && newRoot.Defined() {
		return errInjectedIndexFailure
	}
	return f.inner.Update(ctx, namespace, newRoot, oldRoot, arcs)
}

func (f *failingMaterializer) Snapshot(ctx context.Context, namespace string, root cid.Cid) (arcset.ArcSet, error) {
	return f.inner.Snapshot(ctx, namespace, root)
}

func (f *failingMaterializer) Iterate(ctx context.Context, namespace string, root cid.Cid) arcset.Iterator {
	return f.inner.Iterate(ctx, namespace, root)
}

var errInjectedIndexFailure = errors.New("injected materializer failure")

// rootDeletingFailingMaterializer simulates a non-atomic Materializer backend that has
// already invalidated oldRoot before the logical root-publishing write fails.
// Retrying the original writer operation against oldRoot cannot recover from
// this state; the captured MaterializationDelta must be replayed instead.
type rootDeletingFailingMaterializer struct {
	inner materializer.Store
	store *materialmemory.Store
	fail  bool
}

func (f *rootDeletingFailingMaterializer) Get(ctx context.Context, namespace string, root cid.Cid, path arcset.Path) (cid.Cid, error) {
	return f.inner.Get(ctx, namespace, root, path)
}

func (f *rootDeletingFailingMaterializer) BatchGet(ctx context.Context, namespace string, root cid.Cid, paths []arcset.Path) (map[arcset.Path]cid.Cid, error) {
	return f.inner.BatchGet(ctx, namespace, root, paths)
}

func (f *rootDeletingFailingMaterializer) Update(ctx context.Context, namespace string, newRoot, oldRoot cid.Cid, arcs arcset.ArcSet) error {
	if f.fail && newRoot.Defined() && oldRoot.Defined() {
		f.store.DeleteRoot(namespace, oldRoot)
		return errInjectedIndexFailure
	}
	return f.inner.Update(ctx, namespace, newRoot, oldRoot, arcs)
}

func (f *rootDeletingFailingMaterializer) Snapshot(ctx context.Context, namespace string, root cid.Cid) (arcset.ArcSet, error) {
	return f.inner.Snapshot(ctx, namespace, root)
}

func (f *rootDeletingFailingMaterializer) Iterate(ctx context.Context, namespace string, root cid.Cid) arcset.Iterator {
	return f.inner.Iterate(ctx, namespace, root)
}

// partialArcFailingMaterializer simulates a non-atomic batch failure after one arc
// from a multi-arc delta has already been applied. That intermediate namespace
// state is neither MaterializationBase nor the full expected-after state, so
// RetryMaterializationWrite must fail closed: it cannot distinguish this partial write
// from a later successful subset write.
type partialArcFailingMaterializer struct {
	inner materializer.Store
	store *materialmemory.Store
	fail  bool
}

func (f *partialArcFailingMaterializer) Get(ctx context.Context, namespace string, root cid.Cid, path arcset.Path) (cid.Cid, error) {
	return f.inner.Get(ctx, namespace, root, path)
}

func (f *partialArcFailingMaterializer) BatchGet(ctx context.Context, namespace string, root cid.Cid, paths []arcset.Path) (map[arcset.Path]cid.Cid, error) {
	return f.inner.BatchGet(ctx, namespace, root, paths)
}

func (f *partialArcFailingMaterializer) Update(ctx context.Context, namespace string, newRoot, oldRoot cid.Cid, arcs arcset.ArcSet) error {
	if f.fail && newRoot.Defined() && oldRoot.Defined() {
		arcMap, err := arcset.ToPathMap(arcs)
		if err != nil {
			return err
		}
		previous, err := f.inner.Snapshot(ctx, namespace, oldRoot)
		if err != nil {
			return err
		}
		partial, err := arcset.ToPathMap(previous)
		if err != nil {
			return err
		}
		f.store.DeleteRoot(namespace, oldRoot)
		path := arcset.CanonicalizePath("a")
		target, ok := arcMap[path]
		if !ok || !target.Defined() {
			return errInjectedIndexFailure
		}
		partial[path] = target
		f.store.ReplaceRoot(namespace, newRoot, partial)
		return errInjectedIndexFailure
	}
	return f.inner.Update(ctx, namespace, newRoot, oldRoot, arcs)
}

func (f *partialArcFailingMaterializer) Snapshot(ctx context.Context, namespace string, root cid.Cid) (arcset.ArcSet, error) {
	return f.inner.Snapshot(ctx, namespace, root)
}

func (f *partialArcFailingMaterializer) Iterate(ctx context.Context, namespace string, root cid.Cid) arcset.Iterator {
	return f.inner.Iterate(ctx, namespace, root)
}

// newFailingTestWriter builds a writer whose Materializer Update is controlled by
// the returned *failingMaterializer. The semantic layer is real (radix over
// overwrite Materializer), so it commits a cryptographically valid newRoot before
// the materialization write is attempted.
func newFailingTestWriter(t *testing.T) (*Writer, *failingMaterializer) {
	t.Helper()
	e := materialmemory.New(false)
	scheme, err := kzg.NewScheme()
	if err != nil {
		t.Fatalf("NewScheme: %v", err)
	}
	// The semantic layer writes its radix node slots through the same Materializer
	// instance, so wrap once and share it. Node-slot writes go through Update
	// too; we only fail the *logical* materialization write by toggling fail at the right
	// moment in each test.
	wrapped := &failingMaterializer{inner: e}
	maps, err := radix.NewMap(scheme, wrapped)
	if err != nil {
		t.Fatalf("NewMap: %v", err)
	}
	return NewWriter(maps, wrapped), wrapped
}

func newRootDeletingFailureWriter(t *testing.T) (*Writer, *rootDeletingFailingMaterializer) {
	t.Helper()
	e := materialmemory.New(false)
	scheme, err := kzg.NewScheme()
	if err != nil {
		t.Fatalf("NewScheme: %v", err)
	}
	wrapped := &rootDeletingFailingMaterializer{inner: e, store: e}
	maps, err := radix.NewMap(scheme, wrapped)
	if err != nil {
		t.Fatalf("NewMap: %v", err)
	}
	return NewWriter(maps, wrapped), wrapped
}

func newPartialArcFailureWriter(t *testing.T) (*Writer, *partialArcFailingMaterializer) {
	t.Helper()
	e := materialmemory.New(false)
	scheme, err := kzg.NewScheme()
	if err != nil {
		t.Fatalf("NewScheme: %v", err)
	}
	wrapped := &partialArcFailingMaterializer{inner: e, store: e}
	maps, err := radix.NewMap(scheme, wrapped)
	if err != nil {
		t.Fatalf("NewMap: %v", err)
	}
	return NewWriter(maps, wrapped), wrapped
}

func TestApply_MaterializationRetry(t *testing.T) {
	ctx := context.Background()
	namespace := "retry"

	t.Run("success and repeated retry", func(t *testing.T) {
		w, failing := newFailingTestWriter(t)
		root, before := createRetryMap(t, w, namespace)
		newA := makeCIDLocal(t, "new-a")
		mut := retryMapMutation(t, root, before, map[string]cid.Cid{"a": newA})
		failing.fail = true
		_, err := w.Apply(ctx, namespace, mut)
		failure := requireMaterializationFailure(t, err)
		requireRetryTargets(t, failing, namespace, root, before)

		// A retry can fail again without losing the original transition.
		err = failure.RetryMaterializationWrite(ctx, failing)
		retryFailure := requireMaterializationFailure(t, err)
		if !retryFailure.NewRoot.Equals(failure.NewRoot) || !retryFailure.OldRoot.Equals(root) {
			t.Fatal("retry changed the captured roots")
		}
		failing.fail = false
		if err := w.RetryMaterializationWrite(ctx, retryFailure); err != nil {
			t.Fatalf("Writer.RetryMaterializationWrite: %v", err)
		}
		before["a"] = newA
		requireRetryTargets(t, failing, namespace, failure.NewRoot, before)
		if err := failure.RetryMaterializationWrite(ctx, failing); err != nil {
			t.Fatalf("retry of the already applied transition: %v", err)
		}
		requireRetryTargets(t, failing, namespace, failure.NewRoot, before)
	})

	t.Run("missing base root mapping", func(t *testing.T) {
		w, failing := newRootDeletingFailureWriter(t)
		root, before := createRetryMap(t, w, namespace)
		newA := makeCIDLocal(t, "new-a")
		failing.fail = true
		_, err := w.Apply(ctx, namespace, retryMapMutation(t, root, before, map[string]cid.Cid{"a": newA}))
		failing.fail = false
		failure := requireMaterializationFailure(t, err)
		if _, err := failing.Snapshot(ctx, namespace, root); !errors.Is(err, materializer.ErrNotFound) {
			t.Fatalf("Snapshot(base root) = %v, want ErrNotFound", err)
		}
		requireRetryTargets(t, failing, namespace, cid.Undef, before)
		if err := failure.RetryMaterializationWrite(ctx, failing); err != nil {
			t.Fatalf("retry without base root mapping: %v", err)
		}
		before["a"] = newA
		requireRetryTargets(t, failing, namespace, failure.NewRoot, before)
	})

	t.Run("later write rejects stale replay", func(t *testing.T) {
		w, failing := newFailingTestWriter(t)
		root, before := createRetryMap(t, w, namespace)
		failing.fail = true
		_, err := w.Apply(ctx, namespace, retryMapMutation(t, root, before, map[string]cid.Cid{"a": makeCIDLocal(t, "stale-a")}))
		failing.fail = false
		failure := requireMaterializationFailure(t, err)
		laterA := makeCIDLocal(t, "later-a")
		later, err := w.Apply(ctx, namespace, retryMapMutation(t, root, before, map[string]cid.Cid{"a": laterA}))
		if err != nil {
			t.Fatalf("later Apply: %v", err)
		}
		before["a"] = laterA
		requireRetryTargets(t, failing, namespace, later.NewRoot, before)
		calls := failing.calls
		if err := w.RetryMaterializationWrite(ctx, failure); !errors.Is(err, ErrStaleMaterialization) {
			t.Fatalf("stale retry = %v, want ErrStaleMaterialization", err)
		}
		if failing.calls != calls {
			t.Fatal("stale retry reached Materializer.Update")
		}
		requireRetryTargets(t, failing, namespace, later.NewRoot, before)
	})

	t.Run("partial delta is rejected", func(t *testing.T) {
		w, failing := newPartialArcFailureWriter(t)
		root, before := createRetryMap(t, w, namespace)
		newA := makeCIDLocal(t, "new-a")
		failing.fail = true
		_, err := w.Apply(ctx, namespace, retryMapMutation(t, root, before, map[string]cid.Cid{
			"a": newA, "b": makeCIDLocal(t, "new-b"),
		}))
		failing.fail = false
		failure := requireMaterializationFailure(t, err)
		before["a"] = newA
		requireRetryTargets(t, failing, namespace, failure.NewRoot, before)
		if err := failure.RetryMaterializationWrite(ctx, failing); !errors.Is(err, ErrStaleMaterialization) {
			t.Fatalf("retry after partial write = %v, want ErrStaleMaterialization", err)
		}
		requireRetryTargets(t, failing, namespace, failure.NewRoot, before)
	})

	t.Run("later subset write is not partial progress", func(t *testing.T) {
		w, failing := newFailingTestWriter(t)
		root, before := createRetryMap(t, w, namespace)
		batchA := makeCIDLocal(t, "batch-a")
		failing.fail = true
		_, err := w.Apply(ctx, namespace, retryMapMutation(t, root, before, map[string]cid.Cid{
			"a": batchA, "b": makeCIDLocal(t, "batch-b"),
		}))
		failing.fail = false
		failure := requireMaterializationFailure(t, err)
		later, err := w.Apply(ctx, namespace, retryMapMutation(t, root, before, map[string]cid.Cid{"a": batchA}))
		if err != nil {
			t.Fatalf("later subset Apply: %v", err)
		}
		before["a"] = batchA
		requireRetryTargets(t, failing, namespace, later.NewRoot, before)
		calls := failing.calls
		if err := failure.RetryMaterializationWrite(ctx, failing); !errors.Is(err, ErrStaleMaterialization) {
			t.Fatalf("retry after subset write = %v, want ErrStaleMaterialization", err)
		}
		if failing.calls != calls {
			t.Fatal("stale retry reached Materializer.Update")
		}
		requireRetryTargets(t, failing, namespace, later.NewRoot, before)
	})
}

func createRetryMap(t *testing.T, w *Writer, namespace string) (cid.Cid, map[string]cid.Cid) {
	t.Helper()
	values := map[string]cid.Cid{
		"@payload": makeCIDLocal(t, "payload"),
		"a":        makeCIDLocal(t, "value-a"),
		"b":        makeCIDLocal(t, "value-b"),
	}
	root, err := w.CreateStructure(context.Background(), namespace, checkedArcSet(values))
	if err != nil {
		t.Fatalf("CreateStructure: %v", err)
	}
	return root, values
}

func retryMapMutation(t *testing.T, root cid.Cid, before, updates map[string]cid.Cid) coremutation.SemanticMutation {
	t.Helper()
	changes := make([]arcset.ArcChange, 0, len(updates))
	for path, target := range updates {
		changes = append(changes, arcset.ArcChange{
			Coordinate: mustMapCoordinate(t, path),
			Before:     targetRefPtr(arcset.NewCASTarget(before[path])),
			After:      targetRefPtr(arcset.NewCASTarget(target)),
		})
	}
	return coremutation.SemanticMutation{
		BaseRoot: root,
		Deltas: []coremutation.ArcSetDelta{{
			Object: root, Kind: arcset.KindMap,
			Changes: mustWriterDelta(t, arcset.KindMap, changes),
		}},
	}
}

func requireMaterializationFailure(t *testing.T, err error) *MaterializationWriteFailedError {
	t.Helper()
	var failure *MaterializationWriteFailedError
	if !errors.As(err, &failure) || !errors.Is(err, errInjectedIndexFailure) {
		t.Fatalf("expected injected MaterializationWriteFailedError, got %T: %v", err, err)
	}
	if !failure.NewRoot.Defined() || failure.MaterializationDelta == nil || failure.MaterializationBase == nil {
		t.Fatalf("failure missing exact retry material: %+v", failure)
	}
	return failure
}

func requireRetryTargets(t *testing.T, table materializer.Snapshotter, namespace string, root cid.Cid, want map[string]cid.Cid) {
	t.Helper()
	view, err := table.Snapshot(context.Background(), namespace, root)
	if err != nil {
		t.Fatalf("Snapshot(%s): %v", root, err)
	}
	got, err := arcset.ToPathMap(view)
	if err != nil {
		t.Fatalf("ToPathMap: %v", err)
	}
	// This narrow wrapper uses the node-store fallback, which also keeps
	// semantic node slots in the snapshot. Check every logical map target.
	for path, target := range want {
		if !got[arcset.CanonicalizePath(path)].Equals(target) {
			t.Fatalf("snapshot %s = %s, want %s", path, got[arcset.CanonicalizePath(path)], target)
		}
	}
}

func makeCIDLocal(t *testing.T, data string) cid.Cid {
	t.Helper()
	mhash, err := mh.Sum([]byte(data), mh.SHA2_256, -1)
	if err != nil {
		t.Fatalf("mh.Sum: %v", err)
	}
	return cid.NewCidV1(cid.Raw, mhash)
}

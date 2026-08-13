package writer

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"sync"
	"testing"

	"github.com/dewebprotocol/malt/auth/arcset"
	materializer "github.com/dewebprotocol/malt/auth/arcset/materializer"
	materialmemory "github.com/dewebprotocol/malt/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt/auth/commitment/kzg"
	"github.com/dewebprotocol/malt/auth/semantic/list"
	listtree "github.com/dewebprotocol/malt/auth/semantic/list/tree"
	"github.com/dewebprotocol/malt/auth/semantic/mapping"
	mappingradix "github.com/dewebprotocol/malt/auth/semantic/mapping/radix"
	"github.com/dewebprotocol/malt/wire/maltcid"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

// Test helpers.

func newTestWriter(t *testing.T) (*Writer, *materialmemory.Store, mapping.Semantics, *materialmemory.Store) {
	t.Helper()
	e := materialmemory.New(false)

	// KZG commitment scheme
	scheme, err := kzg.NewScheme()
	if err != nil {
		t.Fatalf("failed to create KZG scheme: %v", err)
	}

	semantic, err := mappingradix.NewMap(scheme, e)
	if err != nil {
		t.Fatalf("failed to create mapping semantic: %v", err)
	}

	w := NewWriter(semantic, e)

	return w, e, semantic, e
}

func newTestWriterWithList(t *testing.T) (*Writer, *materialmemory.Store, mapping.Semantics, list.Semantics, *materialmemory.Store) {
	t.Helper()

	e := materialmemory.New(false)
	scheme, err := kzg.NewScheme()
	if err != nil {
		t.Fatalf("failed to create KZG scheme: %v", err)
	}
	semantic, err := mappingradix.NewMap(scheme, e)
	if err != nil {
		t.Fatalf("failed to create mapping semantic: %v", err)
	}
	listSemantic, err := listtree.NewList(scheme, e)
	if err != nil {
		t.Fatalf("failed to create list semantic: %v", err)
	}

	w := NewWriter(semantic, e, listSemantic)
	return w, e, semantic, listSemantic, e
}

type errArcSet struct {
	arcs []struct {
		path   arcset.Path
		target cid.Cid
	}
	err error
}

func (s errArcSet) Get(path arcset.Path) (cid.Cid, bool) {
	for _, arc := range s.arcs {
		if arc.path == path {
			return arc.target, true
		}
	}
	return cid.Undef, false
}

func (s errArcSet) Iterate() arcset.Iterator {
	return &errArcIterator{arcs: s.arcs, err: s.err}
}

func (s errArcSet) Len() int {
	return len(s.arcs)
}

type errArcIterator struct {
	arcs []struct {
		path   arcset.Path
		target cid.Cid
	}
	err   error
	index int
}

func (it *errArcIterator) Next() (arcset.Path, cid.Cid, bool) {
	if it.index >= len(it.arcs) {
		return "", cid.Undef, false
	}
	arc := it.arcs[it.index]
	it.index++
	return arc.path, arc.target, true
}

func (it *errArcIterator) Err() error {
	return it.err
}

func (it *errArcIterator) Close() {}

type nonComparableMaterializer struct {
	materializer materializer.Store
	tags         []string
}

type identifiedNonComparableMaterializer struct {
	nonComparableMaterializer
	identity string
}

func (t identifiedNonComparableMaterializer) FreshnessIdentity() string { return t.identity }

type interfaceWrappedMaterializer struct {
	materializer.Store
}

type firstIdentifiedMaterializer struct {
	materializer.Store
	identity string
}

func (t firstIdentifiedMaterializer) FreshnessIdentity() string { return t.identity }

type secondIdentifiedMaterializer struct {
	materializer.Store
	identity string
}

func (t secondIdentifiedMaterializer) FreshnessIdentity() string { return t.identity }

type fixedWidthCommitOnlySemantics struct {
	list.Semantics
	committer list.FixedWidthCommitter
}

func (s fixedWidthCommitOnlySemantics) CommitFixed(ctx context.Context, namespace string, chunks []cid.Cid, chunkSize, totalSize uint64) (cid.Cid, error) {
	return s.committer.CommitFixed(ctx, namespace, chunks, chunkSize, totalSize)
}

type fixedWidthAppendOnlySemantics struct {
	list.Semantics
	appender list.FixedWidthAppender
}

type countingBatchMapSemantics struct {
	mapping.Semantics
	updateCalls      int
	batchUpdateCalls int
}

func (s *countingBatchMapSemantics) Update(ctx context.Context, namespace string, root cid.Cid, key arcset.Path, oldValue, newValue cid.Cid) (cid.Cid, error) {
	s.updateCalls++
	return s.Semantics.Update(ctx, namespace, root, key, oldValue, newValue)
}

func (s *countingBatchMapSemantics) BatchUpdate(ctx context.Context, namespace string, root cid.Cid, updates []mapping.BatchUpdate) (cid.Cid, error) {
	s.batchUpdateCalls++
	return s.Semantics.BatchUpdate(ctx, namespace, root, updates)
}

func (s fixedWidthAppendOnlySemantics) AppendFixed(ctx context.Context, namespace string, root cid.Cid, key cid.Cid, totalSize uint64) (cid.Cid, uint64, error) {
	return s.appender.AppendFixed(ctx, namespace, root, key, totalSize)
}

func (t nonComparableMaterializer) Get(ctx context.Context, namespace string, root cid.Cid, path arcset.Path) (cid.Cid, error) {
	return t.materializer.Get(ctx, namespace, root, path)
}

func (t nonComparableMaterializer) BatchGet(ctx context.Context, namespace string, root cid.Cid, paths []arcset.Path) (map[arcset.Path]cid.Cid, error) {
	return t.materializer.BatchGet(ctx, namespace, root, paths)
}

func (t nonComparableMaterializer) Update(ctx context.Context, namespace string, newRoot, oldRoot cid.Cid, arcs arcset.ArcSet) error {
	return t.materializer.Update(ctx, namespace, newRoot, oldRoot, arcs)
}

func (t nonComparableMaterializer) Snapshot(ctx context.Context, namespace string, root cid.Cid) (arcset.ArcSet, error) {
	return t.materializer.Snapshot(ctx, namespace, root)
}

func (t nonComparableMaterializer) Iterate(ctx context.Context, namespace string, root cid.Cid) arcset.Iterator {
	return t.materializer.Iterate(ctx, namespace, root)
}

type batchGetProbeMaterializer struct {
	materializer  materializer.Store
	getErr        error
	batchGetErr   error
	getCalls      int
	batchGetCalls int
}

func (t *batchGetProbeMaterializer) Get(ctx context.Context, namespace string, root cid.Cid, path arcset.Path) (cid.Cid, error) {
	t.getCalls++
	if t.getErr != nil {
		return cid.Undef, t.getErr
	}
	return t.materializer.Get(ctx, namespace, root, path)
}

func (t *batchGetProbeMaterializer) BatchGet(ctx context.Context, namespace string, root cid.Cid, paths []arcset.Path) (map[arcset.Path]cid.Cid, error) {
	t.batchGetCalls++
	if t.batchGetErr != nil {
		return nil, t.batchGetErr
	}
	return t.materializer.BatchGet(ctx, namespace, root, paths)
}

func (t *batchGetProbeMaterializer) Update(ctx context.Context, namespace string, newRoot, oldRoot cid.Cid, arcs arcset.ArcSet) error {
	return t.materializer.Update(ctx, namespace, newRoot, oldRoot, arcs)
}

func (t *batchGetProbeMaterializer) Snapshot(ctx context.Context, namespace string, root cid.Cid) (arcset.ArcSet, error) {
	return t.materializer.Snapshot(ctx, namespace, root)
}

func (t *batchGetProbeMaterializer) Iterate(ctx context.Context, namespace string, root cid.Cid) arcset.Iterator {
	return t.materializer.Iterate(ctx, namespace, root)
}

func fakeCID(seed string) cid.Cid {
	mhash, _ := mh.Sum([]byte(seed), mh.SHA2_256, -1)
	return cid.NewCidV1(cid.Raw, mhash)
}

func mustTypedRoot(t *testing.T, kind maltcid.SemanticKind) cid.Cid {
	t.Helper()

	scheme, err := kzg.NewScheme()
	if err != nil {
		t.Fatalf("kzg.NewScheme failed: %v", err)
	}
	root, err := scheme.Commit(nil)
	if err != nil {
		t.Fatalf("scheme.Commit failed: %v", err)
	}
	commitment, err := maltcid.ExtractCommitment(root)
	if err != nil {
		t.Fatalf("ExtractCommitment failed: %v", err)
	}
	typed, err := maltcid.NewTypedCID(kind, maltcid.BackendKindKZG, commitment)
	if err != nil {
		t.Fatalf("NewTypedCID failed: %v", err)
	}
	return typed
}

func makeArcSet(pairs map[string]cid.Cid) *arcset.Set {
	out := make(map[string]cid.Cid, len(pairs)+1)
	for path, target := range pairs {
		out[path] = target
	}
	if _, ok := out["@payload"]; !ok {
		out["@payload"] = fakeCID("payload")
	}
	return arcset.NewSetFrom(out)
}

func mustWriterDelta(t *testing.T, kind arcset.Kind, changes []arcset.ArcChange) *arcset.CanonicalArcDelta {
	t.Helper()
	delta, err := arcset.NewCanonicalArcDelta(kind, changes)
	if err != nil {
		t.Fatalf("NewCanonicalArcDelta failed: %v", err)
	}
	return delta
}

func mustMapCoordinate(t *testing.T, path string) arcset.CanonicalCoordinate {
	t.Helper()
	coord, err := arcset.NewMapCoordinate(path)
	if err != nil {
		t.Fatalf("NewMapCoordinate failed: %v", err)
	}
	return coord
}

func mustListCoordinate(t *testing.T, index int64) arcset.CanonicalCoordinate {
	t.Helper()
	coord, err := arcset.NewListCoordinate(index)
	if err != nil {
		t.Fatalf("NewListCoordinate failed: %v", err)
	}
	return coord
}

func targetRefPtr(target arcset.TargetRef) *arcset.TargetRef {
	return &target
}

// Tests.

func TestValidateSemanticMutationRejectsInvalidShape(t *testing.T) {
	root := fakeCID("root")
	payload := fakeCID("payload")
	mapDelta := mustWriterDelta(t, arcset.KindMap, []arcset.ArcChange{{
		Coordinate: mustMapCoordinate(t, "@payload"),
		After:      targetRefPtr(arcset.NewCASTarget(payload)),
	}})
	listDelta := mustWriterDelta(t, arcset.KindList, []arcset.ArcChange{{
		Coordinate: mustListCoordinate(t, 0),
		After:      targetRefPtr(arcset.NewCASTarget(payload)),
	}})

	tests := []struct {
		name string
		mut  SemanticMutation
		want error
	}{
		{
			name: "missing base root",
			mut: SemanticMutation{
				Deltas: []ArcSetDelta{{
					Object:  root,
					Kind:    arcset.KindMap,
					Changes: mapDelta,
				}},
			},
			want: ErrInvalidBaseRoot,
		},
		{
			name: "empty deltas",
			mut: SemanticMutation{
				BaseRoot: root,
			},
			want: ErrEmptyDeltas,
		},
		{
			name: "nil delta",
			mut: SemanticMutation{
				BaseRoot: root,
				Deltas: []ArcSetDelta{{
					Object: root,
					Kind:   arcset.KindMap,
				}},
			},
			want: ErrNilDelta,
		},
		{
			name: "delta kind mismatch",
			mut: SemanticMutation{
				BaseRoot: root,
				Deltas: []ArcSetDelta{{
					Object:  root,
					Kind:    arcset.KindMap,
					Changes: listDelta,
				}},
			},
			want: ErrObjectKindMismatch,
		},
		{
			name: "object kind mismatch",
			mut: SemanticMutation{
				BaseRoot: root,
				Deltas: []ArcSetDelta{{
					Object:  mustTypedRoot(t, maltcid.SemanticKindList),
					Kind:    arcset.KindMap,
					Changes: mapDelta,
				}},
			},
			want: ErrObjectKindMismatch,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSemanticMutation(tt.mut)
			if !errors.Is(err, tt.want) {
				t.Fatalf("ValidateSemanticMutation error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestValidateSemanticMutationIsRootCentric(t *testing.T) {
	root := fakeCID("root-centric-base")
	payload := fakeCID("root-centric-payload")
	delta := mustWriterDelta(t, arcset.KindMap, []arcset.ArcChange{{
		Coordinate: mustMapCoordinate(t, "@payload"),
		After:      targetRefPtr(arcset.NewCASTarget(payload)),
	}})

	err := ValidateSemanticMutation(SemanticMutation{
		BaseRoot: root,
		Deltas: []ArcSetDelta{{
			Object:  root,
			Kind:    arcset.KindMap,
			Changes: delta,
		}},
	})
	if err != nil {
		t.Fatalf("ValidateSemanticMutation failed without bucket id: %v", err)
	}
}

func TestWriterApplySemanticMapMutation(t *testing.T) {
	w, _, _, _ := newTestWriter(t)
	ctx := context.Background()
	namespace := "test"
	oldChild := fakeCID("old-child")
	newChild := fakeCID("new-child")

	snapshot, err := arcset.NewArcSet(map[string]cid.Cid{
		"child": oldChild,
	})
	if err != nil {
		t.Fatalf("NewArcSet failed: %v", err)
	}
	root, err := w.CreateStructure(ctx, namespace, snapshot)
	if err != nil {
		t.Fatalf("CreateStructure failed: %v", err)
	}

	receipt, err := w.Apply(ctx, namespace, SemanticMutation{
		BaseRoot: root,
		Deltas: []ArcSetDelta{{
			Object: root,
			Kind:   arcset.KindMap,
			Changes: mustWriterDelta(t, arcset.KindMap, []arcset.ArcChange{{
				Coordinate: mustMapCoordinate(t, "child"),
				Before:     targetRefPtr(arcset.NewMapTarget(oldChild)),
				After:      targetRefPtr(arcset.NewMapTarget(newChild)),
			}}),
		}},
	})
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	if receipt.DeltaCount != 1 || receipt.ArcCount != 1 {
		t.Fatalf("receipt counts = deltas %d arcs %d, want 1/1", receipt.DeltaCount, receipt.ArcCount)
	}

	got, err := w.GetArc(ctx, namespace, receipt.NewRoot, "child")
	if err != nil {
		t.Fatalf("GetArc failed: %v", err)
	}
	if !got.Equals(newChild) {
		t.Fatalf("child target = %s, want %s", got, newChild)
	}
}

func TestWriterApplySemanticMapMutationUsesOneBatch(t *testing.T) {
	w, _, semantic, _ := newTestWriter(t)
	ctx := context.Background()
	namespace := "test-batched-semantic-mutation"
	oldA := fakeCID("old-a")
	oldB := fakeCID("old-b")
	newA := fakeCID("new-a")
	newB := fakeCID("new-b")

	snapshot, err := arcset.NewArcSet(map[string]cid.Cid{
		"a": oldA,
		"b": oldB,
	})
	if err != nil {
		t.Fatalf("NewArcSet failed: %v", err)
	}
	root, err := w.CreateStructure(ctx, namespace, snapshot)
	if err != nil {
		t.Fatalf("CreateStructure failed: %v", err)
	}
	counting := &countingBatchMapSemantics{Semantics: semantic}
	w.semantic = counting

	receipt, err := w.Apply(ctx, namespace, SemanticMutation{
		BaseRoot: root,
		Deltas: []ArcSetDelta{{
			Object: root,
			Kind:   arcset.KindMap,
			Changes: mustWriterDelta(t, arcset.KindMap, []arcset.ArcChange{
				{
					Coordinate: mustMapCoordinate(t, "a"),
					Before:     targetRefPtr(arcset.NewMapTarget(oldA)),
					After:      targetRefPtr(arcset.NewMapTarget(newA)),
				},
				{
					Coordinate: mustMapCoordinate(t, "b"),
					Before:     targetRefPtr(arcset.NewMapTarget(oldB)),
					After:      targetRefPtr(arcset.NewMapTarget(newB)),
				},
			}),
		}},
	})
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	if counting.batchUpdateCalls != 1 || counting.updateCalls != 0 {
		t.Fatalf("semantic calls = BatchUpdate %d Update %d, want 1/0", counting.batchUpdateCalls, counting.updateCalls)
	}
	for path, want := range map[string]cid.Cid{"a": newA, "b": newB} {
		got, err := w.GetArc(ctx, namespace, receipt.NewRoot, path)
		if err != nil {
			t.Fatalf("GetArc(%s) failed: %v", path, err)
		}
		if !got.Equals(want) {
			t.Fatalf("%s target = %s, want %s", path, got, want)
		}
	}
}

func TestWriterApplySemanticMapCreateWithoutPayload(t *testing.T) {
	w, _, _, _ := newTestWriter(t)
	ctx := context.Background()
	target := fakeCID("profile-name")

	receipt, err := w.Apply(ctx, "generic-map", SemanticMutation{
		BaseRoot: fakeCID("application-base"),
		Deltas: []ArcSetDelta{{
			Kind: arcset.KindMap,
			Changes: mustWriterDelta(t, arcset.KindMap, []arcset.ArcChange{{
				Coordinate: mustMapCoordinate(t, "profile/name"),
				After:      targetRefPtr(arcset.NewCASTarget(target)),
			}}),
		}},
	})
	if err != nil {
		t.Fatalf("Apply generic map create failed: %v", err)
	}
	got, err := w.GetArc(ctx, "generic-map", receipt.NewRoot, "profile/name")
	if err != nil {
		t.Fatalf("GetArc failed: %v", err)
	}
	if !got.Equals(target) {
		t.Fatalf("profile/name target = %s, want %s", got, target)
	}
}

func TestWriterApplySemanticListCreateMutation(t *testing.T) {
	w, _, _, lists, _ := newTestWriterWithList(t)
	ctx := context.Background()
	namespace := "test"
	first := fakeCID("first")
	second := fakeCID("second")

	receipt, err := w.Apply(ctx, namespace, SemanticMutation{
		BaseRoot: fakeCID("base"),
		Deltas: []ArcSetDelta{{
			Kind: arcset.KindList,
			Changes: mustWriterDelta(t, arcset.KindList, []arcset.ArcChange{
				{Coordinate: mustListCoordinate(t, 0), After: targetRefPtr(arcset.NewCASTarget(first))},
				{Coordinate: mustListCoordinate(t, 1), After: targetRefPtr(arcset.NewCASTarget(second))},
			}),
		}},
	})
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	query, proof, err := lists.Prove(ctx, namespace, receipt.NewRoot, 1)
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}
	if query.Length != 2 || !query.Key.Equals(second) {
		t.Fatalf("query = %+v, want length 2 key %s", query, second)
	}
	ok, err := lists.Verify(receipt.NewRoot, 1, query, proof)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !ok {
		t.Fatal("list proof did not verify")
	}
}

func TestWriterApplySemanticListAppendMutation(t *testing.T) {
	w, _, _, lists, _ := newTestWriterWithList(t)
	ctx := context.Background()
	namespace := "test"
	first := fakeCID("first")
	second := fakeCID("second")
	third := fakeCID("third")
	root, err := lists.Commit(ctx, namespace, list.NewViewFromSlice([]cid.Cid{first, second}))
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	receipt, err := w.Apply(ctx, namespace, SemanticMutation{
		BaseRoot: root,
		Deltas: []ArcSetDelta{{
			Object: root,
			Kind:   arcset.KindList,
			Changes: mustWriterDelta(t, arcset.KindList, []arcset.ArcChange{{
				Coordinate: mustListCoordinate(t, 2),
				After:      targetRefPtr(arcset.NewCASTarget(third)),
			}}),
		}},
	})
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	query, proof, err := lists.Prove(ctx, namespace, receipt.NewRoot, 2)
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}
	if query.Length != 3 || !query.Key.Equals(third) {
		t.Fatalf("query = %+v, want length 3 key %s", query, third)
	}
	ok, err := lists.Verify(receipt.NewRoot, 2, query, proof)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !ok {
		t.Fatal("list proof did not verify")
	}
}

func TestWriterApplyFixedMeasuredListCreateWithCommitOnlySemantics(t *testing.T) {
	_, table, semantic, lists, _ := newTestWriterWithList(t)
	ctx := context.Background()
	namespace := "fixed-commit-only"
	chunkSize := uint64(4)
	chunks := []cid.Cid{fakeCID("fixed-commit-only-0"), fakeCID("fixed-commit-only-1")}
	fixed := lists.(list.FixedWidthSemantics)
	commitOnly := fixedWidthCommitOnlySemantics{
		Semantics: lists,
		committer: fixed,
	}
	if _, ok := any(commitOnly).(list.FixedWidthAppender); ok {
		t.Fatal("commit-only fixture unexpectedly implements FixedWidthAppender")
	}
	w := NewWriter(semantic, table, commitOnly)

	expectedRoot, err := fixed.CommitFixed(ctx, namespace, chunks, chunkSize, uint64(len(chunks))*chunkSize)
	if err != nil {
		t.Fatalf("CommitFixed expected failed: %v", err)
	}
	receipt, err := w.Apply(ctx, namespace, SemanticMutation{
		BaseRoot: fakeCID("fixed-commit-only-base"),
		Deltas: []ArcSetDelta{{
			ExpectedRoot: expectedRoot,
			Kind:         arcset.KindList,
			Changes: mustWriterDelta(t, arcset.KindList, []arcset.ArcChange{
				{Coordinate: mustListCoordinate(t, 0), After: targetRefPtr(arcset.NewCASTarget(chunks[0]))},
				{Coordinate: mustListCoordinate(t, 1), After: targetRefPtr(arcset.NewCASTarget(chunks[1]))},
			}),
			Commit: CommitDescriptor{FixedList: &FixedListCommit{
				ChunkSize: chunkSize,
				TotalSize: uint64(len(chunks)) * chunkSize,
			}},
		}},
	})
	if err != nil {
		t.Fatalf("Apply with CommitFixed-only semantics failed: %v", err)
	}
	if !receipt.NewRoot.Equals(expectedRoot) {
		t.Fatalf("new root = %s, want %s", receipt.NewRoot, expectedRoot)
	}
}

func TestWriterApplyFixedMeasuredListAppendMutation(t *testing.T) {
	_, table, semantic, lists, _ := newTestWriterWithList(t)
	ctx := context.Background()
	namespace := "test"
	chunkSize := uint64(4)
	chunks := make([]cid.Cid, 256)
	for i := range chunks {
		chunks[i] = fakeCID("fixed-chunk-" + strconv.Itoa(i))
	}
	fixed := lists.(list.FixedWidthSemantics)
	appendOnly := fixedWidthAppendOnlySemantics{
		Semantics: lists,
		appender:  fixed,
	}
	if _, ok := any(appendOnly).(list.FixedWidthCommitter); ok {
		t.Fatal("append-only fixture unexpectedly implements FixedWidthCommitter")
	}
	w := NewWriter(semantic, table, appendOnly)
	baseRoot, err := fixed.CommitFixed(ctx, namespace, chunks[:255], chunkSize, uint64(255)*chunkSize)
	if err != nil {
		t.Fatalf("CommitFixed base failed: %v", err)
	}
	expectedRoot, err := fixed.CommitFixed(ctx, namespace, chunks, chunkSize, uint64(256)*chunkSize)
	if err != nil {
		t.Fatalf("CommitFixed expected failed: %v", err)
	}

	receipt, err := w.Apply(ctx, namespace, SemanticMutation{
		BaseRoot: baseRoot,
		Deltas: []ArcSetDelta{{
			Object:       baseRoot,
			ExpectedRoot: expectedRoot,
			Kind:         arcset.KindList,
			Changes: mustWriterDelta(t, arcset.KindList, []arcset.ArcChange{{
				Coordinate: mustListCoordinate(t, 255),
				After:      targetRefPtr(arcset.NewCASTarget(chunks[255])),
			}}),
			Commit: CommitDescriptor{
				FixedList: &FixedListCommit{
					TotalSize: uint64(256) * chunkSize,
					ChunkSize: chunkSize,
				},
			},
		}},
	})
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	if !receipt.NewRoot.Equals(expectedRoot) {
		t.Fatalf("new root = %s, want %s", receipt.NewRoot, expectedRoot)
	}
}

func TestWriter_UpdateArc_Insert(t *testing.T) {
	w, _, _, _ := newTestWriter(t)
	ctx := context.Background()
	namespace := "test"

	// Create initial structure
	arcs := makeArcSet(map[string]cid.Cid{
		"a": fakeCID("data-a"),
		"b": fakeCID("data-b"),
	})
	root, err := w.CreateStructure(ctx, namespace, arcs)
	if err != nil {
		t.Fatalf("CreateStructure failed: %v", err)
	}
	if !root.Defined() {
		t.Fatal("root not defined after CreateStructure")
	}

	// Insert a new arc
	newTarget := fakeCID("data-c")
	result, err := w.UpdateArc(ctx, namespace, root, "c", newTarget)
	if err != nil {
		t.Fatalf("UpdateArc insert failed: %v", err)
	}

	if result.Op != ArcInsert {
		t.Errorf("expected ArcInsert, got %v", result.Op)
	}
	if !result.NewRoot.Defined() {
		t.Error("newRoot not defined")
	}
	if result.NewRoot.Equals(root) {
		t.Error("newRoot should differ from oldRoot after insert")
	}
	if result.NewTarget != newTarget {
		t.Errorf("newTarget mismatch: expected %s, got %s", newTarget, result.NewTarget)
	}

	// Verify the new arc is accessible
	target, err := w.GetArc(ctx, namespace, result.NewRoot, "c")
	if err != nil {
		t.Fatalf("GetArc failed after insert: %v", err)
	}
	if target != newTarget {
		t.Errorf("getArc returned wrong target: expected %s, got %s", newTarget, target)
	}

	// Verify old arcs are still accessible
	for path, expected := range map[string]cid.Cid{"a": fakeCID("data-a"), "b": fakeCID("data-b")} {
		got, err := w.GetArc(ctx, namespace, result.NewRoot, path)
		if err != nil {
			t.Fatalf("GetArc failed for %s: %v", path, err)
		}
		if got != expected {
			t.Errorf("GetArc(%s): expected %s, got %s", path, expected, got)
		}
	}
}

func TestWriter_UpdateArc_Replace(t *testing.T) {
	w, _, _, _ := newTestWriter(t)
	ctx := context.Background()
	namespace := "test"

	arcs := makeArcSet(map[string]cid.Cid{
		"a": fakeCID("data-a"),
		"b": fakeCID("data-b"),
	})
	root, err := w.CreateStructure(ctx, namespace, arcs)
	if err != nil {
		t.Fatalf("CreateStructure failed: %v", err)
	}

	// Replace arc "a"
	newTarget := fakeCID("data-a-new")
	result, err := w.UpdateArc(ctx, namespace, root, "a", newTarget)
	if err != nil {
		t.Fatalf("UpdateArc replace failed: %v", err)
	}

	if result.Op != ArcReplace {
		t.Errorf("expected ArcReplace, got %v", result.Op)
	}
	if result.OldTarget != fakeCID("data-a") {
		t.Errorf("oldTarget wrong: expected %s, got %s", fakeCID("data-a"), result.OldTarget)
	}

	// Verify replacement
	got, err := w.GetArc(ctx, namespace, result.NewRoot, "a")
	if err != nil {
		t.Fatalf("GetArc failed: %v", err)
	}
	if got != newTarget {
		t.Errorf("replaced arc value wrong: expected %s, got %s", newTarget, got)
	}
}

func TestWriter_UpdateArc_Delete(t *testing.T) {
	w, _, _, _ := newTestWriter(t)
	ctx := context.Background()
	namespace := "test"

	arcs := makeArcSet(map[string]cid.Cid{
		"a": fakeCID("data-a"),
		"b": fakeCID("data-b"),
	})
	root, err := w.CreateStructure(ctx, namespace, arcs)
	if err != nil {
		t.Fatalf("CreateStructure failed: %v", err)
	}

	// Delete arc "a"
	result, err := w.UpdateArc(ctx, namespace, root, "a", cid.Undef)
	if err != nil {
		t.Fatalf("UpdateArc delete failed: %v", err)
	}

	if result.Op != ArcDelete {
		t.Errorf("expected ArcDelete, got %v", result.Op)
	}

	// Verify deleted
	_, err = w.GetArc(ctx, namespace, result.NewRoot, "a")
	if err == nil {
		t.Error("expected error after delete, got nil")
	}

	// Arc "b" should still be accessible
	got, err := w.GetArc(ctx, namespace, result.NewRoot, "b")
	if err != nil {
		t.Fatalf("GetArc for 'b' failed: %v", err)
	}
	if got != fakeCID("data-b") {
		t.Errorf("arc 'b' changed after delete of 'a': got %s", got)
	}
}

func TestWriter_UpdateArc_InvalidInputs(t *testing.T) {
	w, _, _, _ := newTestWriter(t)
	ctx := context.Background()
	namespace := "test"

	// Undefined root
	_, err := w.UpdateArc(ctx, namespace, cid.Undef, "a", fakeCID("data"))
	if err != ErrInvalidRoot {
		t.Errorf("expected ErrInvalidRoot, got %v", err)
	}

	// Empty path
	arcs := makeArcSet(map[string]cid.Cid{"a": fakeCID("data-a")})
	root, _ := w.CreateStructure(ctx, namespace, arcs)
	_, err = w.UpdateArc(ctx, namespace, root, "", fakeCID("data"))
	if err != ErrEmptyPath {
		t.Errorf("expected ErrEmptyPath, got %v", err)
	}
}

func TestWriter_UpdateArc_ConcurrentSameRootReturnsStaleRoot(t *testing.T) {
	w, _, _, _ := newTestWriter(t)
	ctx := context.Background()
	namespace := "test-concurrent-update"

	root, err := w.CreateStructure(ctx, namespace, makeArcSet(map[string]cid.Cid{
		"base": fakeCID("base"),
	}))
	if err != nil {
		t.Fatalf("CreateStructure failed: %v", err)
	}

	const workers = 8
	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	roots := make(chan cid.Cid, workers)

	for i := 0; i < workers; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			result, err := w.UpdateArc(ctx, namespace, root, "child-"+strconv.Itoa(i), fakeCID("child-"+strconv.Itoa(i)))
			if err != nil {
				errs <- err
				return
			}
			roots <- result.NewRoot
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	close(roots)

	successes := 0
	for newRoot := range roots {
		successes++
		if !newRoot.Defined() || newRoot.Equals(root) {
			t.Fatalf("successful update returned invalid new root %s", newRoot)
		}
	}
	stale := 0
	for err := range errs {
		if !errors.Is(err, ErrStaleRoot) {
			t.Fatalf("concurrent update error = %v, want ErrStaleRoot", err)
		}
		stale++
	}
	if successes != 1 || stale != workers-1 {
		t.Fatalf("successes/stale = %d/%d, want 1/%d", successes, stale, workers-1)
	}
}

func TestWriter_UpdateArc_SharedMaterializerRejectsConsumedBaseRoot(t *testing.T) {
	w, at, semantic, _ := newTestWriter(t)
	w2 := NewWriter(semantic, at)
	ctx := context.Background()
	namespace := "test-shared-writer"

	root, err := w.CreateStructure(ctx, namespace, makeArcSet(map[string]cid.Cid{
		"base": fakeCID("base"),
	}))
	if err != nil {
		t.Fatalf("CreateStructure failed: %v", err)
	}

	if _, err := w.UpdateArc(ctx, namespace, root, "first", fakeCID("first")); err != nil {
		t.Fatalf("first UpdateArc failed: %v", err)
	}
	_, err = w2.UpdateArc(ctx, namespace, root, "second", fakeCID("second"))
	if !errors.Is(err, ErrStaleRoot) {
		t.Fatalf("second writer UpdateArc error = %v, want ErrStaleRoot", err)
	}
}

func TestWriter_NonComparableMaterializerFailsClosedWithoutIdentity(t *testing.T) {
	_, at, semantic, _ := newTestWriter(t)
	table := materializer.Store(nonComparableMaterializer{
		materializer: at,
		tags:         []string{"custom"},
	})

	w := NewWriter(semantic, table)
	if w.freshness != nil || !errors.Is(w.freshnessErr, ErrFreshnessIdentityUnavailable) {
		t.Fatalf("freshness state = (%p, %v), want unavailable identity", w.freshness, w.freshnessErr)
	}

	root, err := w.CreateStructure(context.Background(), "non-comparable", makeArcSet(map[string]cid.Cid{"base": fakeCID("base")}))
	if err != nil {
		t.Fatalf("CreateStructure failed: %v", err)
	}
	if _, err := w.UpdateArc(context.Background(), "non-comparable", root, "child", fakeCID("child")); !errors.Is(err, ErrFreshnessIdentityUnavailable) {
		t.Fatalf("UpdateArc error = %v, want ErrFreshnessIdentityUnavailable", err)
	}
}

func TestWriter_InterfaceWrappedUnhashableMaterializerFailsClosedWithoutPanic(t *testing.T) {
	_, at, semantic, _ := newTestWriter(t)
	inner := materializer.Store(nonComparableMaterializer{
		materializer: at,
		tags:         []string{"custom"},
	})
	table := materializer.Store(interfaceWrappedMaterializer{Store: inner})
	if !reflect.TypeOf(table).Comparable() {
		t.Fatal("test fixture type must be comparable")
	}
	if reflect.ValueOf(table).Comparable() {
		t.Fatal("test fixture value must be unhashable through its interface field")
	}

	w := NewWriter(semantic, table)
	if w.freshness != nil || !errors.Is(w.freshnessErr, ErrFreshnessIdentityUnavailable) {
		t.Fatalf("freshness state = (%p, %v), want unavailable identity", w.freshness, w.freshnessErr)
	}

	ctx := context.Background()
	namespace := "interface-wrapped-unhashable"
	root, err := w.CreateStructure(ctx, namespace, makeArcSet(map[string]cid.Cid{"base": fakeCID("base")}))
	if err != nil {
		t.Fatalf("CreateStructure failed: %v", err)
	}
	if _, err := w.UpdateArc(ctx, namespace, root, "child", fakeCID("child")); !errors.Is(err, ErrFreshnessIdentityUnavailable) {
		t.Fatalf("UpdateArc error = %v, want ErrFreshnessIdentityUnavailable", err)
	}
}

func TestWriter_ExplicitIdentitySharesAcrossWrapperTypesAndPointerForms(t *testing.T) {
	_, at, semantic, _ := newTestWriter(t)
	const identity = "shared-cross-wrapper-test-backend"
	first := firstIdentifiedMaterializer{Store: at, identity: identity}
	second := secondIdentifiedMaterializer{Store: at, identity: identity}
	pointer := &firstIdentifiedMaterializer{Store: at, identity: identity}

	w := NewWriter(semantic, first)
	w2 := NewWriter(semantic, second)
	w3 := NewWriter(semantic, pointer)
	if w.freshness == nil || w.freshness != w2.freshness || w.freshness != w3.freshness {
		t.Fatal("canonical explicit identity did not share one guard across wrapper types and pointer forms")
	}

	ctx := context.Background()
	namespace := "identified-cross-wrapper"
	root, err := w.CreateStructure(ctx, namespace, makeArcSet(map[string]cid.Cid{"base": fakeCID("base")}))
	if err != nil {
		t.Fatalf("CreateStructure failed: %v", err)
	}
	if _, err := w.UpdateArc(ctx, namespace, root, "first", fakeCID("first")); err != nil {
		t.Fatalf("first UpdateArc failed: %v", err)
	}
	if _, err := w2.UpdateArc(ctx, namespace, root, "second", fakeCID("second")); !errors.Is(err, ErrStaleRoot) {
		t.Fatalf("second wrapper UpdateArc error = %v, want ErrStaleRoot", err)
	}
}

func TestWriter_NonComparableMaterializerSharesExplicitIdentity(t *testing.T) {
	_, at, semantic, _ := newTestWriter(t)
	table := materializer.Store(identifiedNonComparableMaterializer{
		nonComparableMaterializer: nonComparableMaterializer{materializer: at, tags: []string{"custom"}},
		identity:                  "shared-test-backend",
	})

	w := NewWriter(semantic, table)
	w2 := NewWriter(semantic, table)
	if w.freshness == nil || w2.freshness == nil || w.freshness != w2.freshness {
		t.Fatal("explicit freshness identity did not share one guard")
	}

	ctx := context.Background()
	root, err := w.CreateStructure(ctx, "identified-non-comparable", makeArcSet(map[string]cid.Cid{"base": fakeCID("base")}))
	if err != nil {
		t.Fatalf("CreateStructure failed: %v", err)
	}
	if _, err := w.UpdateArc(ctx, "identified-non-comparable", root, "first", fakeCID("first")); err != nil {
		t.Fatalf("first UpdateArc failed: %v", err)
	}
	if _, err := w2.UpdateArc(ctx, "identified-non-comparable", root, "second", fakeCID("second")); !errors.Is(err, ErrStaleRoot) {
		t.Fatalf("second UpdateArc error = %v, want ErrStaleRoot", err)
	}
}

func TestWriter_UpdateArc_AllowsReturnedRootAfterCycle(t *testing.T) {
	w, _, _, _ := newTestWriter(t)
	ctx := context.Background()
	namespace := "test-root-cycle"

	rootA, err := w.CreateStructure(ctx, namespace, makeArcSet(map[string]cid.Cid{
		"base": fakeCID("base"),
	}))
	if err != nil {
		t.Fatalf("CreateStructure failed: %v", err)
	}

	inserted := fakeCID("inserted")
	resultB, err := w.UpdateArc(ctx, namespace, rootA, "temp", inserted)
	if err != nil {
		t.Fatalf("A -> B UpdateArc failed: %v", err)
	}
	rootB := resultB.NewRoot
	if rootB.Equals(rootA) {
		t.Fatal("A -> B should produce a distinct root")
	}

	resultA2, err := w.UpdateArc(ctx, namespace, rootB, "temp", cid.Undef)
	if err != nil {
		t.Fatalf("B -> A UpdateArc failed: %v", err)
	}
	rootA2 := resultA2.NewRoot
	if !rootA2.Equals(rootA) {
		t.Fatalf("B -> A root = %s, want original root %s", rootA2, rootA)
	}

	resultC, err := w.UpdateArc(ctx, namespace, rootA2, "next", fakeCID("next"))
	if err != nil {
		t.Fatalf("A -> C UpdateArc failed after root returned current: %v", err)
	}
	if !resultC.NewRoot.Defined() || resultC.NewRoot.Equals(rootA2) {
		t.Fatalf("A -> C returned invalid root %s", resultC.NewRoot)
	}
}

func TestWriter_CreateStructureRevivesRecreatedRoot(t *testing.T) {
	w, _, _, _ := newTestWriter(t)
	ctx := context.Background()
	namespace := "test-recreated-root"
	arcs := makeArcSet(map[string]cid.Cid{
		"base": fakeCID("base"),
	})

	rootA, err := w.CreateStructure(ctx, namespace, arcs)
	if err != nil {
		t.Fatalf("CreateStructure failed: %v", err)
	}
	resultB, err := w.UpdateArc(ctx, namespace, rootA, "temp", fakeCID("temp"))
	if err != nil {
		t.Fatalf("A -> B UpdateArc failed: %v", err)
	}
	if resultB.NewRoot.Equals(rootA) {
		t.Fatal("A -> B should produce a distinct root")
	}

	rootA2, err := w.CreateStructure(ctx, namespace, arcs)
	if err != nil {
		t.Fatalf("recreate A failed: %v", err)
	}
	if !rootA2.Equals(rootA) {
		t.Fatalf("recreated root = %s, want original root %s", rootA2, rootA)
	}

	resultC, err := w.UpdateArc(ctx, namespace, rootA2, "next", fakeCID("next"))
	if err != nil {
		t.Fatalf("A -> C UpdateArc failed after CreateStructure revived A: %v", err)
	}
	if !resultC.NewRoot.Defined() || resultC.NewRoot.Equals(rootA2) {
		t.Fatalf("A -> C returned invalid root %s", resultC.NewRoot)
	}
}

func TestWriter_UpdateArc_VersionedMaterializerAllowsBranching(t *testing.T) {
	ctx := context.Background()
	namespace := "test-versioned-branch"

	at := materialmemory.New(true)
	scheme, err := kzg.NewScheme()
	if err != nil {
		t.Fatalf("failed to create KZG scheme: %v", err)
	}
	semantic, err := mappingradix.NewMap(scheme, at)
	if err != nil {
		t.Fatalf("failed to create mapping semantic: %v", err)
	}
	w := NewWriter(semantic, at)
	w2 := NewWriter(semantic, at)

	root, err := w.CreateStructure(ctx, namespace, makeArcSet(map[string]cid.Cid{
		"base": fakeCID("base"),
	}))
	if err != nil {
		t.Fatalf("CreateStructure failed: %v", err)
	}

	first, err := w.UpdateArc(ctx, namespace, root, "left", fakeCID("left"))
	if err != nil {
		t.Fatalf("first UpdateArc failed: %v", err)
	}
	second, err := w2.UpdateArc(ctx, namespace, root, "right", fakeCID("right"))
	if err != nil {
		t.Fatalf("second UpdateArc failed: %v", err)
	}

	if !first.NewRoot.Defined() || !second.NewRoot.Defined() {
		t.Fatal("expected both branches to produce defined roots")
	}
	if first.NewRoot.Equals(second.NewRoot) {
		t.Fatal("expected versioned branches to produce distinct roots")
	}
	if got, err := w.GetArc(ctx, namespace, first.NewRoot, "left"); err != nil || !got.Equals(fakeCID("left")) {
		t.Fatalf("left branch lookup = %v, %v", got, err)
	}
	if got, err := w.GetArc(ctx, namespace, second.NewRoot, "right"); err != nil || !got.Equals(fakeCID("right")) {
		t.Fatalf("right branch lookup = %v, %v", got, err)
	}
	if got, err := w.GetArc(ctx, namespace, first.NewRoot, "base"); err != nil || !got.Equals(fakeCID("base")) {
		t.Fatalf("left branch base lookup = %v, %v", got, err)
	}
	if got, err := w.GetArc(ctx, namespace, second.NewRoot, "base"); err != nil || !got.Equals(fakeCID("base")) {
		t.Fatalf("right branch base lookup = %v, %v", got, err)
	}
}

func TestWriter_BatchUpdateArcs(t *testing.T) {
	w, _, _, _ := newTestWriter(t)
	ctx := context.Background()
	namespace := "test"

	arcs := makeArcSet(map[string]cid.Cid{
		"a": fakeCID("data-a"),
		"b": fakeCID("data-b"),
		"c": fakeCID("data-c"),
	})
	root, err := w.CreateStructure(ctx, namespace, arcs)
	if err != nil {
		t.Fatalf("CreateStructure failed: %v", err)
	}

	// Batch update: replace "a", insert "d", delete "c"
	updates := map[string]cid.Cid{
		"a": fakeCID("data-a-new"),
		"d": fakeCID("data-d"),
		"c": cid.Undef,
	}

	result, err := w.BatchUpdateArcs(ctx, namespace, root, updates)
	if err != nil {
		t.Fatalf("BatchUpdateArcs failed: %v", err)
	}

	if !result.NewRoot.Defined() {
		t.Error("newRoot not defined")
	}
	if result.NewRoot.Equals(root) {
		t.Error("newRoot should differ after batch update")
	}

	// Verify per-arc results
	if result.PerArc["a"].Op != ArcReplace {
		t.Errorf("expected ArcReplace for 'a', got %v", result.PerArc["a"].Op)
	}
	if result.PerArc["d"].Op != ArcInsert {
		t.Errorf("expected ArcInsert for 'd', got %v", result.PerArc["d"].Op)
	}
	if result.PerArc["c"].Op != ArcDelete {
		t.Errorf("expected ArcDelete for 'c', got %v", result.PerArc["c"].Op)
	}

	// Verify final state
	checks := map[string]struct {
		expected cid.Cid
		exists   bool
	}{
		"a": {fakeCID("data-a-new"), true},
		"b": {fakeCID("data-b"), true},
		"d": {fakeCID("data-d"), true},
		"c": {cid.Undef, false},
	}

	for path, check := range checks {
		got, err := w.GetArc(ctx, namespace, result.NewRoot, path)
		if check.exists {
			if err != nil {
				t.Fatalf("GetArc(%s) failed: %v", path, err)
			}
			if got != check.expected {
				t.Errorf("GetArc(%s): expected %s, got %s", path, check.expected, got)
			}
		} else {
			if err == nil {
				t.Errorf("expected GetArc(%s) to fail, got %s", path, got)
			}
		}
	}
}

func TestWriter_BatchUpdateArcs_UsesBatchGetForClassification(t *testing.T) {
	baseWriter, e, semantic, _ := newTestWriter(t)
	ctx := context.Background()
	namespace := "test-batchget-classification"

	root, err := baseWriter.CreateStructure(ctx, namespace, makeArcSet(map[string]cid.Cid{
		"a": fakeCID("data-a"),
		"c": fakeCID("data-c"),
	}))
	if err != nil {
		t.Fatalf("CreateStructure failed: %v", err)
	}

	probe := &batchGetProbeMaterializer{
		materializer: e,
		getErr:       errors.New("unexpected per-path Get"),
	}
	w := NewWriter(semantic, probe)
	result, err := w.BatchUpdateArcs(ctx, namespace, root, map[string]cid.Cid{
		"a": fakeCID("data-a-new"),
		"d": fakeCID("data-d"),
		"c": cid.Undef,
	})
	if err != nil {
		t.Fatalf("BatchUpdateArcs failed: %v", err)
	}
	if probe.batchGetCalls != 1 {
		t.Fatalf("BatchGet calls = %d, want 1", probe.batchGetCalls)
	}
	if probe.getCalls != 0 {
		t.Fatalf("Get calls = %d, want 0", probe.getCalls)
	}
	if result.PerArc["a"].Op != ArcReplace {
		t.Fatalf("a op = %v, want replace", result.PerArc["a"].Op)
	}
	if result.PerArc["d"].Op != ArcInsert {
		t.Fatalf("d op = %v, want insert", result.PerArc["d"].Op)
	}
	if result.PerArc["c"].Op != ArcDelete {
		t.Fatalf("c op = %v, want delete", result.PerArc["c"].Op)
	}
}

func TestWriter_BatchUpdateArcs_PropagatesBatchGetError(t *testing.T) {
	baseWriter, e, semantic, _ := newTestWriter(t)
	ctx := context.Background()
	namespace := "test-batchget-error"

	root, err := baseWriter.CreateStructure(ctx, namespace, makeArcSet(map[string]cid.Cid{
		"a": fakeCID("data-a"),
	}))
	if err != nil {
		t.Fatalf("CreateStructure failed: %v", err)
	}

	batchGetErr := errors.New("injected batch get failure")
	probe := &batchGetProbeMaterializer{
		materializer: e,
		batchGetErr:  batchGetErr,
	}
	w := NewWriter(semantic, probe)

	_, err = w.BatchUpdateArcs(ctx, namespace, root, map[string]cid.Cid{
		"a": fakeCID("data-a-new"),
	})
	if !errors.Is(err, batchGetErr) {
		t.Fatalf("BatchUpdateArcs error = %v, want BatchGet error", err)
	}
	if probe.batchGetCalls != 1 {
		t.Fatalf("BatchGet calls = %d, want 1", probe.batchGetCalls)
	}
}

func TestWriter_BatchUpdateArcs_RejectsConsumedBaseRoot(t *testing.T) {
	w, _, _, _ := newTestWriter(t)
	ctx := context.Background()
	namespace := "test-batch-stale"

	root, err := w.CreateStructure(ctx, namespace, makeArcSet(map[string]cid.Cid{
		"a": fakeCID("data-a"),
	}))
	if err != nil {
		t.Fatalf("CreateStructure failed: %v", err)
	}

	first, err := w.BatchUpdateArcs(ctx, namespace, root, map[string]cid.Cid{
		"a": fakeCID("data-a-new"),
	})
	if err != nil {
		t.Fatalf("first BatchUpdateArcs failed: %v", err)
	}

	_, err = w.BatchUpdateArcs(ctx, namespace, root, map[string]cid.Cid{
		"b": fakeCID("data-b"),
	})
	if !errors.Is(err, ErrStaleRoot) {
		t.Fatalf("second BatchUpdateArcs error = %v, want ErrStaleRoot", err)
	}

	got, err := w.GetArc(ctx, namespace, first.NewRoot, "a")
	if err != nil {
		t.Fatalf("GetArc(a) from first root failed: %v", err)
	}
	if !got.Equals(fakeCID("data-a-new")) {
		t.Fatalf("a = %s, want updated target", got)
	}
}

func TestWriter_BatchUpdateArcs_InvalidInputs(t *testing.T) {
	w, _, _, _ := newTestWriter(t)
	ctx := context.Background()
	namespace := "test"

	// Undefined root
	_, err := w.BatchUpdateArcs(ctx, namespace, cid.Undef, map[string]cid.Cid{"a": fakeCID("data")})
	if err != ErrInvalidRoot {
		t.Errorf("expected ErrInvalidRoot, got %v", err)
	}

	// Empty updates
	arcs := makeArcSet(map[string]cid.Cid{"a": fakeCID("data-a")})
	root, _ := w.CreateStructure(ctx, namespace, arcs)
	_, err = w.BatchUpdateArcs(ctx, namespace, root, map[string]cid.Cid{})
	if err == nil {
		t.Error("expected error for empty updates, got nil")
	}
}

func TestWriter_CreateStructure(t *testing.T) {
	w, _, _, _ := newTestWriter(t)
	ctx := context.Background()
	namespace := "test"

	// Create structure with arcs
	arcs := makeArcSet(map[string]cid.Cid{
		"foo": fakeCID("data-foo"),
		"bar": fakeCID("data-bar"),
	})
	root, err := w.CreateStructure(ctx, namespace, arcs)
	if err != nil {
		t.Fatalf("CreateStructure failed: %v", err)
	}
	if !root.Defined() {
		t.Fatal("root not defined")
	}

	// Verify arcs are accessible
	for path, expected := range map[string]cid.Cid{
		"foo": fakeCID("data-foo"),
		"bar": fakeCID("data-bar"),
	} {
		got, err := w.GetArc(ctx, namespace, root, path)
		if err != nil {
			t.Fatalf("GetArc(%s) failed: %v", path, err)
		}
		if got != expected {
			t.Errorf("GetArc(%s): expected %s, got %s", path, expected, got)
		}
	}
}

func TestWriter_CanonicalizesPathsAtWriteBoundary(t *testing.T) {
	w, _, _, _ := newTestWriter(t)
	ctx := context.Background()
	namespace := "test"

	arcs := makeArcSet(map[string]cid.Cid{
		"/foo//bar/": fakeCID("data-foo-bar"),
	})
	root, err := w.CreateStructure(ctx, namespace, arcs)
	if err != nil {
		t.Fatalf("CreateStructure failed: %v", err)
	}

	got, err := w.GetArc(ctx, namespace, root, "foo/bar")
	if err != nil {
		t.Fatalf("GetArc failed: %v", err)
	}
	if got != fakeCID("data-foo-bar") {
		t.Errorf("GetArc(foo/bar): expected %s, got %s", fakeCID("data-foo-bar"), got)
	}

	updated, err := w.UpdateArc(ctx, namespace, root, "/foo//bar/", fakeCID("data-foo-bar-v2"))
	if err != nil {
		t.Fatalf("UpdateArc failed: %v", err)
	}
	got, err = w.GetArc(ctx, namespace, updated.NewRoot, "/foo//bar/")
	if err != nil {
		t.Fatalf("GetArc after update failed: %v", err)
	}
	if got != fakeCID("data-foo-bar-v2") {
		t.Errorf("GetArc after update: expected %s, got %s", fakeCID("data-foo-bar-v2"), got)
	}
}

func TestWriter_CreateStructure_NilArcSet(t *testing.T) {
	w, _, _, _ := newTestWriter(t)
	ctx := context.Background()
	namespace := "test"

	_, err := w.CreateStructure(ctx, namespace, nil)
	if err == nil {
		t.Error("expected error for nil arc set, got nil")
	}
}

func TestWriter_GetArc_NotFound(t *testing.T) {
	w, _, _, _ := newTestWriter(t)
	ctx := context.Background()
	namespace := "test"

	arcs := makeArcSet(map[string]cid.Cid{"a": fakeCID("data-a")})
	root, _ := w.CreateStructure(ctx, namespace, arcs)

	_, err := w.GetArc(ctx, namespace, root, "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent arc, got nil")
	}
}

func TestWriter_GetSnapshot(t *testing.T) {
	w, _, _, _ := newTestWriter(t)
	ctx := context.Background()
	namespace := "test"

	arcs := makeArcSet(map[string]cid.Cid{
		"x": fakeCID("data-x"),
		"y": fakeCID("data-y"),
	})
	root, err := w.CreateStructure(ctx, namespace, arcs)
	if err != nil {
		t.Fatalf("CreateStructure failed: %v", err)
	}

	snapshot, err := w.GetSnapshot(ctx, namespace, root)
	if err != nil {
		t.Fatalf("GetSnapshot failed: %v", err)
	}
	if snapshot.Len() != 3 {
		t.Errorf("expected 3 arcs including @payload, got %d", snapshot.Len())
	}

	target, ok := snapshot.Get(arcset.CanonicalizePath("x"))
	if !ok {
		t.Fatal("arc 'x' not found in snapshot")
	}
	if target != fakeCID("data-x") {
		t.Errorf("snapshot arc 'x' wrong: got %s", target)
	}
}

func TestFilterLogicalArcSetPropagatesErrors(t *testing.T) {
	iterErr := fmt.Errorf("iterator exploded")
	_, err := filterLogicalArcSet(errArcSet{
		arcs: []struct {
			path   arcset.Path
			target cid.Cid
		}{{
			path:   arcset.CanonicalizePath("runtime/internal"),
			target: fakeCID("runtime"),
		}, {
			path:   arcset.CanonicalizePath("a"),
			target: fakeCID("data-a"),
		}},
		err: iterErr,
	})
	if err == nil {
		t.Fatal("filterLogicalArcSet returned nil error for failing iterator")
	}
	if !errors.Is(err, iterErr) {
		t.Fatalf("filterLogicalArcSet error = %v, want %v", err, iterErr)
	}
}

func TestWriter_UpdateArc_UpdateThenGet(t *testing.T) {
	// Verify that after multiple updates, the latest structure root
	// reflects all accumulated changes.
	w, _, _, _ := newTestWriter(t)
	ctx := context.Background()
	namespace := "test"

	arcs := makeArcSet(map[string]cid.Cid{
		"alpha": fakeCID("v0-alpha"),
	})
	root, _ := w.CreateStructure(ctx, namespace, arcs)

	// Update 1: insert "beta"
	r1, err := w.UpdateArc(ctx, namespace, root, "beta", fakeCID("v0-beta"))
	if err != nil {
		t.Fatalf("Update 1 (insert beta) failed: %v", err)
	}

	// Update 2: replace "alpha"
	r2, err := w.UpdateArc(ctx, namespace, r1.NewRoot, "alpha", fakeCID("v1-alpha"))
	if err != nil {
		t.Fatalf("Update 2 (replace alpha) failed: %v", err)
	}

	// Update 3: insert "gamma"
	r3, err := w.UpdateArc(ctx, namespace, r2.NewRoot, "gamma", fakeCID("v0-gamma"))
	if err != nil {
		t.Fatalf("Update 3 (insert gamma) failed: %v", err)
	}

	// Verify final state from r3.NewRoot
	finalRoot := r3.NewRoot
	checks := map[string]cid.Cid{
		"alpha": fakeCID("v1-alpha"),
		"beta":  fakeCID("v0-beta"),
		"gamma": fakeCID("v0-gamma"),
	}
	for path, expected := range checks {
		got, err := w.GetArc(ctx, namespace, finalRoot, path)
		if err != nil {
			t.Fatalf("GetArc(%s) after chain of updates: %v", path, err)
		}
		if got != expected {
			t.Errorf("GetArc(%s) after updates: expected %s, got %s", path, expected, got)
		}
	}
}

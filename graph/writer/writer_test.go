package writer

import (
	"context"
	"errors"
	"strconv"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	materialmemory "github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment/kzg"
	"github.com/dewebprotocol/malt-core/auth/semantic/list"
	listtree "github.com/dewebprotocol/malt-core/auth/semantic/list/tree"
	"github.com/dewebprotocol/malt-core/auth/semantic/mapping"
	mappingradix "github.com/dewebprotocol/malt-core/auth/semantic/mapping/radix"
	coremutation "github.com/dewebprotocol/malt-core/mutation"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
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

func (s fixedWidthAppendOnlySemantics) AppendFixed(ctx context.Context, namespace string, root cid.Cid, key cid.Cid, totalSize uint64) (cid.Cid, uint64, error) {
	return s.appender.AppendFixed(ctx, namespace, root, key, totalSize)
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
	commitment, err := root.CommitmentBytes(maltcid.KZG4096)
	if err != nil {
		t.Fatalf("ExtractCommitment failed: %v", err)
	}
	typed, err := maltcid.NewSemanticRoot(kind, maltcid.BackendKindKZG, commitment)
	if err != nil {
		t.Fatalf("NewSemanticRoot failed: %v", err)
	}
	return typed
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
		mut  coremutation.SemanticMutation
		want error
	}{
		{
			name: "missing base root",
			mut: coremutation.SemanticMutation{
				Deltas: []coremutation.ArcSetDelta{{
					Object:  root,
					Kind:    arcset.KindMap,
					Changes: mapDelta,
				}},
			},
			want: coremutation.ErrInvalidBaseRoot,
		},
		{
			name: "empty deltas",
			mut: coremutation.SemanticMutation{
				BaseRoot: root,
			},
			want: coremutation.ErrEmptyDeltas,
		},
		{
			name: "nil delta",
			mut: coremutation.SemanticMutation{
				BaseRoot: root,
				Deltas: []coremutation.ArcSetDelta{{
					Object: root,
					Kind:   arcset.KindMap,
				}},
			},
			want: coremutation.ErrNilDelta,
		},
		{
			name: "delta kind mismatch",
			mut: coremutation.SemanticMutation{
				BaseRoot: root,
				Deltas: []coremutation.ArcSetDelta{{
					Object:  root,
					Kind:    arcset.KindMap,
					Changes: listDelta,
				}},
			},
			want: coremutation.ErrObjectKindMismatch,
		},
		{
			name: "object kind mismatch",
			mut: coremutation.SemanticMutation{
				BaseRoot: root,
				Deltas: []coremutation.ArcSetDelta{{
					Object:  mustTypedRoot(t, maltcid.SemanticKindList),
					Kind:    arcset.KindMap,
					Changes: mapDelta,
				}},
			},
			want: coremutation.ErrObjectKindMismatch,
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

	err := ValidateSemanticMutation(coremutation.SemanticMutation{
		BaseRoot: root,
		Deltas: []coremutation.ArcSetDelta{{
			Object:  root,
			Kind:    arcset.KindMap,
			Changes: delta,
		}},
	})
	if err != nil {
		t.Fatalf("ValidateSemanticMutation failed without bucket id: %v", err)
	}
}

func TestWriterApplySemanticListCreateMutation(t *testing.T) {
	w, _, _, lists, _ := newTestWriterWithList(t)
	ctx := context.Background()
	namespace := "test"
	first := fakeCID("first")
	second := fakeCID("second")

	receipt, err := w.Apply(ctx, namespace, coremutation.SemanticMutation{
		BaseRoot: fakeCID("base"),
		Deltas: []coremutation.ArcSetDelta{{
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

	receipt, err := w.Apply(ctx, namespace, coremutation.SemanticMutation{
		BaseRoot: root,
		Deltas: []coremutation.ArcSetDelta{{
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
	receipt, err := w.Apply(ctx, namespace, coremutation.SemanticMutation{
		BaseRoot: fakeCID("fixed-commit-only-base"),
		Deltas: []coremutation.ArcSetDelta{{
			ExpectedRoot: expectedRoot,
			Kind:         arcset.KindList,
			Changes: mustWriterDelta(t, arcset.KindList, []arcset.ArcChange{
				{Coordinate: mustListCoordinate(t, 0), After: targetRefPtr(arcset.NewCASTarget(chunks[0]))},
				{Coordinate: mustListCoordinate(t, 1), After: targetRefPtr(arcset.NewCASTarget(chunks[1]))},
			}),
			Commit: coremutation.CommitDescriptor{FixedList: &coremutation.FixedListCommit{
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

	receipt, err := w.Apply(ctx, namespace, coremutation.SemanticMutation{
		BaseRoot: baseRoot,
		Deltas: []coremutation.ArcSetDelta{{
			Object:       baseRoot,
			ExpectedRoot: expectedRoot,
			Kind:         arcset.KindList,
			Changes: mustWriterDelta(t, arcset.KindList, []arcset.ArcChange{{
				Coordinate: mustListCoordinate(t, 255),
				After:      targetRefPtr(arcset.NewCASTarget(chunks[255])),
			}}),
			Commit: coremutation.CommitDescriptor{
				FixedList: &coremutation.FixedListCommit{
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

func TestWriter_CreateStructure_NilArcSet(t *testing.T) {
	w, _, _, _ := newTestWriter(t)
	ctx := context.Background()
	namespace := "test"

	_, err := w.CreateStructure(ctx, namespace, nil)
	if err == nil {
		t.Error("expected error for nil arc set, got nil")
	}
}

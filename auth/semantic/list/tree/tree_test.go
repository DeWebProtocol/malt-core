package tree_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	"github.com/dewebprotocol/malt-core/auth/arcset/materializer"
	materialmemory "github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
	"github.com/dewebprotocol/malt-core/auth/commitment/kzg"
	"github.com/dewebprotocol/malt-core/auth/semantic/list"
	"github.com/dewebprotocol/malt-core/auth/semantic/list/tree"
	"github.com/dewebprotocol/malt-core/auth/semantic/list/tree/internal"
	"github.com/dewebprotocol/malt-core/auth/semantic/nodegeometry"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

type schemeFactory func(t *testing.T) commitment.IndexCommitment

func newPayloadCID(data []byte) cid.Cid {
	sum, err := mh.Sum(data, mh.SHA2_256, -1)
	if err != nil {
		panic(err)
	}
	return cid.NewCidV1(cid.Raw, sum)
}

func listSchemes() map[string]schemeFactory {
	return map[string]schemeFactory{
		"ipa": func(t *testing.T) commitment.IndexCommitment {
			t.Helper()
			scheme, err := ipa.NewScheme()
			if err != nil {
				t.Fatalf("ipa.NewScheme failed: %v", err)
			}
			return scheme
		},
		"kzg": func(t *testing.T) commitment.IndexCommitment {
			t.Helper()
			scheme, err := kzg.NewScheme()
			if err != nil {
				t.Fatalf("kzg.NewScheme failed: %v", err)
			}
			return scheme
		},
	}
}

func makeValues(count int) []cid.Cid {
	values := make([]cid.Cid, count)
	for i := range values {
		values[i] = newPayloadCID([]byte{byte(i), byte(i >> 8), byte(i >> 16), byte(i >> 24)})
	}
	return values
}

func newList(t *testing.T, factory schemeFactory, store *materialmemory.Store) *tree.TreeList {
	t.Helper()

	semantic, _, err := newListWithMaterializer(factory(t), store)
	if err != nil {
		t.Fatalf("newListWithMaterializer failed: %v", err)
	}
	return semantic
}

func newListWithMaterializer(scheme commitment.IndexCommitment, store *materialmemory.Store) (*tree.TreeList, *materialmemory.Store, error) {
	if store == nil {
		store = materialmemory.New(true)
	}
	semantic, err := tree.NewList(scheme, store)
	if err != nil {
		return nil, nil, err
	}
	return semantic, store, nil
}

func geometryForScheme(t *testing.T, scheme commitment.IndexVerifier) nodegeometry.Geometry {
	t.Helper()
	geometry, err := nodegeometry.ForCapacity(scheme.MaxValues())
	if err != nil {
		t.Fatalf("nodegeometry.ForCapacity(%d): %v", scheme.MaxValues(), err)
	}
	return geometry
}

func TestTreeListBackendGeometryBoundaries(t *testing.T) {
	wantGeometry := map[string]struct {
		nodeWidth int
		branching int
	}{
		"ipa": {nodeWidth: 256, branching: 255},
		"kzg": {nodeWidth: 4096, branching: 4095},
	}

	for name, factory := range listSchemes() {
		t.Run(name, func(t *testing.T) {
			geometry := geometryForScheme(t, factory(t))
			want := wantGeometry[name]
			if got := geometry.NodeWidth(); got != want.nodeWidth {
				t.Fatalf("node width = %d, want %d", got, want.nodeWidth)
			}
			if got := geometry.ListBranchingFactor(); got != want.branching {
				t.Fatalf("branching factor = %d, want %d", got, want.branching)
			}
			if got := len(layout.EmptyRootSlots(geometry)); got != want.nodeWidth {
				t.Fatalf("root slots = %d, want %d", got, want.nodeWidth)
			}
			if got := layout.RequiredHeight(geometry, uint64(want.branching)); got != 0 {
				t.Fatalf("height at %d values = %d, want 0", want.branching, got)
			}
			if got := layout.RequiredHeight(geometry, uint64(want.branching+1)); got != 1 {
				t.Fatalf("height at %d values = %d, want 1", want.branching+1, got)
			}
			digits, err := layout.IndexDigits(geometry, uint64(want.branching), 1)
			if err != nil {
				t.Fatalf("IndexDigits at boundary: %v", err)
			}
			if len(digits) != 2 || digits[0] != 1 || digits[1] != 0 {
				t.Fatalf("digits at index %d = %v, want [1 0]", want.branching, digits)
			}
		})
	}
}

func assertVerifiedQuery(t *testing.T, semantic *tree.TreeList, namespace string, root cid.Cid, index uint64, expected list.Query) {
	t.Helper()

	query, proof, err := semantic.Prove(context.Background(), namespace, root, index)
	if err != nil {
		t.Fatalf("Prove(%d) failed: %v", index, err)
	}
	if query.Length != expected.Length {
		t.Fatalf("query length mismatch for %d: want %d got %d", index, expected.Length, query.Length)
	}
	if !query.Key.Equals(expected.Key) {
		t.Fatalf("query key mismatch for %d: want %s got %s", index, expected.Key, query.Key)
	}

	ok, err := semantic.Verify(root, index, query, proof)
	if err != nil {
		t.Fatalf("Verify(%d) failed: %v", index, err)
	}
	if !ok {
		t.Fatalf("Verify(%d) returned false", index)
	}
}

func stripProofStepSlots(t *testing.T, proof []byte) []byte {
	t.Helper()

	var envelope struct {
		MetadataProof  []byte                       `json:"metadata_proof"`
		MetadataTarget []byte                       `json:"metadata_target,omitempty"`
		Steps          []map[string]json.RawMessage `json:"steps,omitempty"`
	}
	if err := json.Unmarshal(proof, &envelope); err != nil {
		t.Fatalf("decode proof envelope: %v", err)
	}
	for _, step := range envelope.Steps {
		delete(step, "slot")
	}
	stripped, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("encode proof envelope without step slots: %v", err)
	}
	return stripped
}

func commitLegacyWidthNode(t *testing.T, ctx context.Context, scheme commitment.IndexCommitment, e materializer.Store, namespace string, values []cid.Cid) cid.Cid {
	t.Helper()

	geometry := geometryForScheme(t, scheme)
	if len(values) > geometry.ListBranchingFactor() {
		t.Fatalf("legacy width helper supports at most %d values", geometry.ListBranchingFactor())
	}
	slots := make([]cid.Cid, geometry.ListBranchingFactor())
	copy(slots, values)
	return commitTestSlots(t, ctx, scheme, e, namespace, slots)
}

func commitTestSlots(t *testing.T, ctx context.Context, scheme commitment.IndexCommitment, e materializer.Store, namespace string, slots []cid.Cid) cid.Cid {
	t.Helper()

	root, err := layout.CommitSlots(scheme, slots)
	if err != nil {
		t.Fatalf("commit slots: %v", err)
	}
	commBytes, err := maltcid.ExtractCommitment(root)
	if err != nil {
		t.Fatalf("extract commitment: %v", err)
	}
	listRoot, err := maltcid.NewTypedCID(maltcid.SemanticKindList, maltcid.BackendKindOf(root), commBytes)
	if err != nil {
		t.Fatalf("wrap list root: %v", err)
	}
	if err := layout.StoreSlots(ctx, e, namespace, listRoot, slots); err != nil {
		t.Fatalf("store slots: %v", err)
	}
	return listRoot
}

func TestTreeListSemanticProofsAndRestart(t *testing.T) {
	ctx := context.Background()
	values := makeValues(300)

	for name, factory := range listSchemes() {
		t.Run(name, func(t *testing.T) {
			kv := materialmemory.New(true)
			namespace := "tree-proof-" + name

			semantic := newList(t, factory, kv)
			root, err := semantic.Commit(ctx, namespace, list.NewViewFromSlice(values))
			if err != nil {
				t.Fatalf("Commit failed: %v", err)
			}
			if maltcid.SemanticKindOf(root) != maltcid.SemanticKindList {
				t.Fatalf("root semantic kind = %s, want %s", maltcid.SemanticKindOf(root), maltcid.SemanticKindList)
			}
			if name == "kzg" && maltcid.BackendKindOf(root) != maltcid.BackendKindKZG {
				t.Fatalf("root backend kind = %s, want %s", maltcid.BackendKindOf(root), maltcid.BackendKindKZG)
			}
			if name == "ipa" && maltcid.BackendKindOf(root) != maltcid.BackendKindIPA {
				t.Fatalf("root backend kind = %s, want %s", maltcid.BackendKindOf(root), maltcid.BackendKindIPA)
			}

			for _, index := range []uint64{0, 254, 255, 256, 299} {
				assertVerifiedQuery(t, semantic, namespace, root, index, list.Query{
					Key:    values[index],
					Length: uint64(len(values)),
				})
			}

			assertVerifiedQuery(t, semantic, namespace, root, 999, list.Query{
				Key:    cid.Undef,
				Length: uint64(len(values)),
			})

			restarted := newList(t, factory, kv)
			assertVerifiedQuery(t, restarted, namespace, root, 256, list.Query{
				Key:    values[256],
				Length: uint64(len(values)),
			})
		})
	}
}

func TestTreeListRejectsLegacyWidthMaterialization(t *testing.T) {
	ctx := context.Background()
	values := makeValues(2)

	for name, factory := range listSchemes() {
		t.Run(name, func(t *testing.T) {
			kv := materialmemory.New(true)
			namespace := "tree-legacy-width-" + name
			scheme := factory(t)
			_, e, err := newListWithMaterializer(scheme, kv)
			if err != nil {
				t.Fatalf("newListWithMaterializer failed: %v", err)
			}
			root := commitLegacyWidthNode(t, ctx, scheme, e, namespace, values)

			restarted, err := tree.NewList(scheme, e)
			if err != nil {
				t.Fatalf("NewList after restart failed: %v", err)
			}
			if _, _, err := restarted.Prove(ctx, namespace, root, 0); !errors.Is(err, materializer.ErrIncomplete) {
				t.Fatalf("Prove error = %v, want ErrIncomplete", err)
			}
		})
	}
}

func TestTreeListReportsIncompleteMaterialization(t *testing.T) {
	ctx := context.Background()
	for name, factory := range listSchemes() {
		t.Run(name, func(t *testing.T) {
			scheme := factory(t)
			source, _, err := newListWithMaterializer(scheme, materialmemory.New(true))
			if err != nil {
				t.Fatal(err)
			}
			root, err := source.Commit(ctx, "source-"+name, list.NewViewFromSlice(makeValues(2)))
			if err != nil {
				t.Fatal(err)
			}
			missing, _, err := newListWithMaterializer(scheme, materialmemory.New(true))
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := missing.Prove(ctx, "missing-"+name, root, 0); !errors.Is(err, materializer.ErrIncomplete) {
				t.Fatalf("Prove error = %v, want ErrIncomplete", err)
			}
		})
	}
}

func TestTreeListRejectsAuthenticatedLengthWithMissingLeaf(t *testing.T) {
	ctx := context.Background()
	for name, factory := range listSchemes() {
		t.Run(name, func(t *testing.T) {
			scheme := factory(t)
			store := materialmemory.New(true)
			semantic, _, err := newListWithMaterializer(scheme, store)
			if err != nil {
				t.Fatal(err)
			}
			geometry := geometryForScheme(t, scheme)
			slots := layout.EmptyRootSlots(geometry)
			slots[0], err = layout.EncodeNodeMetadata(layout.NodeMetadata{ChildCount: 1})
			if err != nil {
				t.Fatal(err)
			}
			root, err := layout.CommitSlots(scheme, slots)
			if err != nil {
				t.Fatal(err)
			}
			if err := layout.StoreSlots(ctx, store, "missing-leaf-"+name, root, slots); err != nil {
				t.Fatal(err)
			}
			if _, _, err := semantic.Prove(ctx, "missing-leaf-"+name, root, 0); !errors.Is(err, materializer.ErrIncomplete) {
				t.Fatalf("Prove error = %v, want ErrIncomplete", err)
			}
		})
	}
}

func TestTreeListPreservesMaterializerFailure(t *testing.T) {
	ctx := context.Background()
	storeErr := errors.New("materializer unavailable")
	for name, factory := range listSchemes() {
		t.Run(name, func(t *testing.T) {
			scheme := factory(t)
			source, _, err := newListWithMaterializer(scheme, materialmemory.New(true))
			if err != nil {
				t.Fatal(err)
			}
			root, err := source.Commit(ctx, "source-"+name, list.NewViewFromSlice(makeValues(2)))
			if err != nil {
				t.Fatal(err)
			}
			failing, err := tree.NewList(scheme, failingNodeStore{err: storeErr})
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = failing.Prove(ctx, "failing-"+name, root, 0)
			if !errors.Is(err, storeErr) || errors.Is(err, materializer.ErrIncomplete) {
				t.Fatalf("Prove error = %v, want original materializer failure only", err)
			}
		})
	}
}

type failingNodeStore struct {
	err error
}

func (s failingNodeStore) Get(context.Context, string, cid.Cid, arcset.Path) (cid.Cid, error) {
	return cid.Undef, s.err
}

func (s failingNodeStore) BatchGet(context.Context, string, cid.Cid, []arcset.Path) (map[arcset.Path]cid.Cid, error) {
	return nil, s.err
}

func (s failingNodeStore) Update(context.Context, string, cid.Cid, cid.Cid, arcset.ArcSet) error {
	return s.err
}

func TestTreeListVerifiesProofWithoutStepSlots(t *testing.T) {
	ctx := context.Background()
	values := makeValues(300)
	index := uint64(1)

	for name, factory := range listSchemes() {
		t.Run(name, func(t *testing.T) {
			kv := materialmemory.New(true)
			namespace := "tree-proof-without-slots-" + name

			semantic := newList(t, factory, kv)
			root, err := semantic.Commit(ctx, namespace, list.NewViewFromSlice(values))
			if err != nil {
				t.Fatalf("Commit failed: %v", err)
			}
			query, proof, err := semantic.Prove(ctx, namespace, root, index)
			if err != nil {
				t.Fatalf("Prove(%d) failed: %v", index, err)
			}
			strippedProof := stripProofStepSlots(t, proof)

			ok, err := semantic.Verify(root, index, query, strippedProof)
			if err != nil {
				t.Fatalf("Verify(%d) failed: %v", index, err)
			}
			if !ok {
				t.Fatalf("Verify(%d) returned false", index)
			}
		})
	}
}

func TestTreeListAppendIntoChildUpdatesSlotZeroMetadata(t *testing.T) {
	ctx := context.Background()

	for name, factory := range listSchemes() {
		t.Run(name, func(t *testing.T) {
			kv := materialmemory.New(true)
			namespace := "tree-child-append-" + name
			scheme := factory(t)
			geometry := geometryForScheme(t, scheme)
			branching := geometry.ListBranchingFactor()
			values := makeValues(branching + 1)
			restarted, e, err := newListWithMaterializer(scheme, kv)
			if err != nil {
				t.Fatalf("newListWithMaterializer failed: %v", err)
			}
			root, err := restarted.Commit(ctx, namespace, list.NewViewFromSlice(values))
			if err != nil {
				t.Fatalf("Commit failed: %v", err)
			}
			appended := newPayloadCID([]byte("appended to child"))
			appendedRoot, appendedIndex, err := restarted.Append(ctx, namespace, root, appended)
			if err != nil {
				t.Fatalf("Append into child failed: %v", err)
			}
			if appendedIndex != uint64(len(values)) {
				t.Fatalf("append index = %d, want %d", appendedIndex, len(values))
			}

			assertVerifiedQuery(t, restarted, namespace, appendedRoot, 0, list.Query{
				Key:    values[0],
				Length: uint64(len(values) + 1),
			})
			assertVerifiedQuery(t, restarted, namespace, appendedRoot, uint64(branching), list.Query{
				Key:    values[branching],
				Length: uint64(len(values) + 1),
			})
			assertVerifiedQuery(t, restarted, namespace, appendedRoot, appendedIndex, list.Query{
				Key:    appended,
				Length: uint64(len(values) + 1),
			})

			secondChildRoot, err := e.Get(ctx, namespace, cid.Undef, layout.NodeSlotPath(appendedRoot, 2))
			if err != nil {
				t.Fatalf("fetch second child root: %v", err)
			}
			secondChildSlots, err := layout.LoadSlots(ctx, e, namespace, secondChildRoot, geometry.NodeWidth())
			if err != nil {
				t.Fatalf("load second child slots: %v", err)
			}
			meta, err := layout.DecodeNodeMetadata(secondChildSlots[0])
			if err != nil {
				t.Fatalf("decode second child metadata: %v", err)
			}
			if meta.ChildCount != uint64(len(values)+1-branching) {
				t.Fatalf("second child count = %d, want %d", meta.ChildCount, len(values)+1-branching)
			}
		})
	}
}

func TestTreeListChildNodesCarryAuthenticatedMetadata(t *testing.T) {
	ctx := context.Background()

	for name, factory := range listSchemes() {
		t.Run(name, func(t *testing.T) {
			kv := materialmemory.New(true)
			namespace := "tree-child-meta-" + name
			scheme := factory(t)
			geometry := geometryForScheme(t, scheme)
			branching := geometry.ListBranchingFactor()
			values := makeValues(branching + 1)
			semantic, e, err := newListWithMaterializer(scheme, kv)
			if err != nil {
				t.Fatalf("newListWithMaterializer failed: %v", err)
			}

			root, err := semantic.Commit(ctx, namespace, list.NewViewFromSlice(values))
			if err != nil {
				t.Fatalf("Commit failed: %v", err)
			}

			childRoot, err := e.Get(ctx, namespace, cid.Undef, layout.NodeSlotPath(root, 1))
			if err != nil {
				t.Fatalf("fetch first child root: %v", err)
			}
			childSlots, err := layout.LoadSlots(ctx, e, namespace, childRoot, geometry.NodeWidth())
			if err != nil {
				t.Fatalf("load child slots: %v", err)
			}
			childMeta, err := layout.DecodeNodeMetadata(childSlots[0])
			if err != nil {
				t.Fatalf("decode child metadata: %v", err)
			}
			if childMeta.ChildCount != uint64(branching) {
				t.Fatalf("child length = %d, want %d", childMeta.ChildCount, branching)
			}
			if !childSlots[1].Equals(values[0]) {
				t.Fatalf("child logical index 0 stored at slot 1 = %s, want %s", childSlots[1], values[0])
			}
		})
	}
}

func TestTreeListMeasuredChildNodesCarryRangeMetadata(t *testing.T) {
	ctx := context.Background()
	chunkSize := uint64(4)

	for name, factory := range listSchemes() {
		t.Run(name, func(t *testing.T) {
			kv := materialmemory.New(true)
			namespace := "tree-child-range-meta-" + name
			scheme := factory(t)
			geometry := geometryForScheme(t, scheme)
			branching := geometry.ListBranchingFactor()
			chunks := makeValues(branching + 1)
			totalSize := uint64(len(chunks)-1)*chunkSize + 3
			semantic, e, err := newListWithMaterializer(scheme, kv)
			if err != nil {
				t.Fatalf("newListWithMaterializer failed: %v", err)
			}

			root, err := semantic.CommitFixed(ctx, namespace, chunks, chunkSize, totalSize)
			if err != nil {
				t.Fatalf("CommitFixed failed: %v", err)
			}

			firstChildRoot, err := e.Get(ctx, namespace, cid.Undef, layout.NodeSlotPath(root, 1))
			if err != nil {
				t.Fatalf("fetch first child root: %v", err)
			}
			firstChildSlots, err := layout.LoadSlots(ctx, e, namespace, firstChildRoot, geometry.NodeWidth())
			if err != nil {
				t.Fatalf("load first child slots: %v", err)
			}
			firstMeta, err := layout.DecodeNodeMetadata(firstChildSlots[0])
			if err != nil {
				t.Fatalf("decode first child fixed metadata: %v", err)
			}
			if firstMeta.ChildCount != uint64(branching) || firstMeta.TotalSize != uint64(branching)*chunkSize || firstMeta.ChunkSize != chunkSize {
				t.Fatalf("first child metadata = %+v, want count=%d total=%d chunk=%d", firstMeta, branching, uint64(branching)*chunkSize, chunkSize)
			}

			secondChildRoot, err := e.Get(ctx, namespace, cid.Undef, layout.NodeSlotPath(root, 2))
			if err != nil {
				t.Fatalf("fetch second child root: %v", err)
			}
			secondChildSlots, err := layout.LoadSlots(ctx, e, namespace, secondChildRoot, geometry.NodeWidth())
			if err != nil {
				t.Fatalf("load second child slots: %v", err)
			}
			secondMeta, err := layout.DecodeNodeMetadata(secondChildSlots[0])
			if err != nil {
				t.Fatalf("decode second child fixed metadata: %v", err)
			}
			wantSecondSize := totalSize - uint64(branching)*chunkSize
			if secondMeta.ChildCount != uint64(len(chunks)-branching) || secondMeta.TotalSize != wantSecondSize || secondMeta.ChunkSize != chunkSize {
				t.Fatalf("second child metadata = %+v, want count=%d total=%d chunk=%d", secondMeta, len(chunks)-branching, wantSecondSize, chunkSize)
			}
			if !secondChildSlots[1].Equals(chunks[branching]) {
				t.Fatalf("second child logical index 0 stored at slot 1 = %s, want %s", secondChildSlots[1], chunks[branching])
			}
		})
	}
}

func TestTreeListPlainRangeReportsNotMeasured(t *testing.T) {
	ctx := context.Background()
	for name, factory := range listSchemes() {
		t.Run(name, func(t *testing.T) {
			semantic := newList(t, factory, materialmemory.New(true))
			root, err := semantic.Commit(ctx, "tree-plain-range-"+name, list.NewViewFromSlice(makeValues(1)))
			if err != nil {
				t.Fatalf("Commit failed: %v", err)
			}
			end := uint64(0)
			if _, _, err := semantic.ProveRange(ctx, "tree-plain-range-"+name, root, 0, &end); !errors.Is(err, list.ErrNotMeasured) {
				t.Fatalf("ProveRange error = %v, want ErrNotMeasured", err)
			}
		})
	}
}

func TestTreeListFixedRangeProofsUseOptionalEnd(t *testing.T) {
	ctx := context.Background()
	chunks := makeValues(5)
	chunkSize := uint64(4)
	totalSize := uint64(18)

	for name, factory := range listSchemes() {
		t.Run(name, func(t *testing.T) {
			kv := materialmemory.New(true)
			namespace := "tree-fixed-range-" + name

			semantic := newList(t, factory, kv)
			root, err := semantic.CommitFixed(ctx, namespace, chunks, chunkSize, totalSize)
			if err != nil {
				t.Fatalf("CommitFixed failed: %v", err)
			}

			assertVerifiedQuery(t, semantic, namespace, root, 4, list.Query{
				Key:    chunks[4],
				Length: uint64(len(chunks)),
			})

			end := uint64(10)
			result, proof, err := semantic.ProveRange(ctx, namespace, root, 3, &end)
			if err != nil {
				t.Fatalf("ProveRange bounded failed: %v", err)
			}
			if result.Metadata.ChildCount != uint64(len(chunks)) {
				t.Fatalf("child count = %d, want %d", result.Metadata.ChildCount, len(chunks))
			}
			if result.Metadata.TotalSize != totalSize {
				t.Fatalf("total size = %d, want %d", result.Metadata.TotalSize, totalSize)
			}
			if result.Metadata.ChunkSize != chunkSize {
				t.Fatalf("chunk size = %d, want %d", result.Metadata.ChunkSize, chunkSize)
			}
			wantBounded := chunks[:3]
			if len(result.Segments) != len(wantBounded) {
				t.Fatalf("bounded segment count = %d, want %d", len(result.Segments), len(wantBounded))
			}
			for i, want := range wantBounded {
				if !result.Segments[i].Equals(want) {
					t.Fatalf("bounded segment %d = %s, want %s", i, result.Segments[i], want)
				}
			}
			ok, err := semantic.VerifyRange(root, 3, &end, result, proof)
			if err != nil {
				t.Fatalf("VerifyRange bounded failed: %v", err)
			}
			if !ok {
				t.Fatal("VerifyRange bounded returned false")
			}

			toEOF, proof, err := semantic.ProveRange(ctx, namespace, root, 12, nil)
			if err != nil {
				t.Fatalf("ProveRange EOF failed: %v", err)
			}
			wantEOF := chunks[3:]
			if len(toEOF.Segments) != len(wantEOF) {
				t.Fatalf("EOF segment count = %d, want %d", len(toEOF.Segments), len(wantEOF))
			}
			for i, want := range wantEOF {
				if !toEOF.Segments[i].Equals(want) {
					t.Fatalf("EOF segment %d = %s, want %s", i, toEOF.Segments[i], want)
				}
			}
			ok, err = semantic.VerifyRange(root, 12, nil, toEOF, proof)
			if err != nil {
				t.Fatalf("VerifyRange EOF failed: %v", err)
			}
			if !ok {
				t.Fatal("VerifyRange EOF returned false")
			}

			tampered := result
			tampered.Segments = append([]cid.Cid(nil), result.Segments...)
			tampered.Segments[1] = newPayloadCID([]byte("wrong segment"))
			ok, err = semantic.VerifyRange(root, 3, &end, tampered, proof)
			if err != nil {
				t.Fatalf("VerifyRange tampered failed: %v", err)
			}
			if ok {
				t.Fatal("VerifyRange accepted tampered segment CID")
			}

			if _, _, err := semantic.Append(ctx, namespace, root, newPayloadCID([]byte("new chunk"))); err == nil {
				t.Fatal("Append should reject fixed measured list roots")
			}
			if _, err := semantic.Truncate(ctx, namespace, root, uint64(len(chunks)-1)); err == nil {
				t.Fatal("Truncate should reject fixed measured list roots")
			}
		})
	}
}

func TestTreeListSemanticUpdates(t *testing.T) {
	ctx := context.Background()
	initial := makeValues(255)

	for name, factory := range listSchemes() {
		t.Run(name, func(t *testing.T) {
			kv := materialmemory.New(true)
			namespace := "tree-update-" + name

			semantic := newList(t, factory, kv)
			root, err := semantic.Commit(ctx, namespace, list.NewViewFromSlice(initial))
			if err != nil {
				t.Fatalf("Commit failed: %v", err)
			}

			replacement := newPayloadCID([]byte("replacement"))
			replacedRoot, err := semantic.Replace(ctx, namespace, root, 128, initial[128], replacement)
			if err != nil {
				t.Fatalf("Replace failed: %v", err)
			}
			assertVerifiedQuery(t, semantic, namespace, replacedRoot, 128, list.Query{
				Key:    replacement,
				Length: uint64(len(initial)),
			})

			appended := newPayloadCID([]byte("appended"))
			appendedRoot, newIndex, err := semantic.Append(ctx, namespace, replacedRoot, appended)
			if err != nil {
				t.Fatalf("Append failed: %v", err)
			}
			if newIndex != uint64(len(initial)) {
				t.Fatalf("unexpected append index %d", newIndex)
			}
			assertVerifiedQuery(t, semantic, namespace, appendedRoot, newIndex, list.Query{
				Key:    appended,
				Length: uint64(len(initial) + 1),
			})
			assertVerifiedQuery(t, semantic, namespace, appendedRoot, 128, list.Query{
				Key:    replacement,
				Length: uint64(len(initial) + 1),
			})

			truncatedRoot, err := semantic.Truncate(ctx, namespace, appendedRoot, 128)
			if err != nil {
				t.Fatalf("Truncate failed: %v", err)
			}
			assertVerifiedQuery(t, semantic, namespace, truncatedRoot, 127, list.Query{
				Key:    initial[127],
				Length: 128,
			})
			assertVerifiedQuery(t, semantic, namespace, truncatedRoot, 128, list.Query{
				Key:    cid.Undef,
				Length: 128,
			})

			restarted := newList(t, factory, kv)
			assertVerifiedQuery(t, restarted, namespace, truncatedRoot, 127, list.Query{
				Key:    initial[127],
				Length: 128,
			})
		})
	}
}

func TestTreeListEmptyAndRegrow(t *testing.T) {
	ctx := context.Background()

	for name, factory := range listSchemes() {
		t.Run(name, func(t *testing.T) {
			kv := materialmemory.New(true)
			namespace := "tree-empty-" + name

			semantic := newList(t, factory, kv)
			root, err := semantic.Commit(ctx, namespace, list.NewViewFromSlice(nil))
			if err != nil {
				t.Fatalf("Commit(empty) failed: %v", err)
			}

			assertVerifiedQuery(t, semantic, namespace, root, 0, list.Query{
				Key:    cid.Undef,
				Length: 0,
			})

			appended := newPayloadCID([]byte("first"))
			appendedRoot, index, err := semantic.Append(ctx, namespace, root, appended)
			if err != nil {
				t.Fatalf("Append(empty) failed: %v", err)
			}
			if index != 0 {
				t.Fatalf("unexpected append index %d", index)
			}
			assertVerifiedQuery(t, semantic, namespace, appendedRoot, 0, list.Query{
				Key:    appended,
				Length: 1,
			})

			truncatedRoot, err := semantic.Truncate(ctx, namespace, appendedRoot, 0)
			if err != nil {
				t.Fatalf("Truncate(to zero) failed: %v", err)
			}
			assertVerifiedQuery(t, semantic, namespace, truncatedRoot, 0, list.Query{
				Key:    cid.Undef,
				Length: 0,
			})

			restarted := newList(t, factory, kv)
			assertVerifiedQuery(t, restarted, namespace, truncatedRoot, 0, list.Query{
				Key:    cid.Undef,
				Length: 0,
			})
		})
	}
}

func TestTreeListRejectsUndefinedCommittedKeys(t *testing.T) {
	ctx := context.Background()

	for name, factory := range listSchemes() {
		t.Run(name, func(t *testing.T) {
			kv := materialmemory.New(true)
			namespace := "tree-undefined-" + name
			semantic := newList(t, factory, kv)

			if _, err := semantic.Commit(ctx, namespace, list.NewViewFromSlice([]cid.Cid{newPayloadCID([]byte("a")), cid.Undef})); err == nil {
				t.Fatal("Commit should reject undefined committed keys")
			}

			root, err := semantic.Commit(ctx, namespace, list.NewViewFromSlice([]cid.Cid{newPayloadCID([]byte("a"))}))
			if err != nil {
				t.Fatalf("Commit(valid) failed: %v", err)
			}
			if _, _, err := semantic.Append(ctx, namespace, root, cid.Undef); err == nil {
				t.Fatal("Append should reject undefined key")
			}
			if _, err := semantic.Replace(ctx, namespace, root, 0, newPayloadCID([]byte("a")), cid.Undef); err == nil {
				t.Fatal("Replace should reject undefined new key")
			}
		})
	}
}

func TestTreeListRejectsCorruptedMaterialization(t *testing.T) {
	ctx := context.Background()

	for name, factory := range listSchemes() {
		t.Run(name, func(t *testing.T) {
			kv := materialmemory.New(true)
			namespace := "tree-corrupt-" + name
			scheme := factory(t)
			geometry := geometryForScheme(t, scheme)
			branching := geometry.ListBranchingFactor()
			values := makeValues(branching + 1)
			semantic, e, err := newListWithMaterializer(scheme, kv)
			if err != nil {
				t.Fatalf("newListWithMaterializer failed: %v", err)
			}

			root, err := semantic.Commit(ctx, namespace, list.NewViewFromSlice(values))
			if err != nil {
				t.Fatalf("Commit failed: %v", err)
			}

			childRoot, err := e.Get(ctx, namespace, cid.Undef, arcset.CanonicalizePath(layout.NodeSlotPath(root, 2).String()))
			if err != nil {
				t.Fatalf("failed to fetch child root: %v", err)
			}

			corruptValue := newPayloadCID([]byte("corrupt-child-slot"))
			if err := e.Update(ctx, namespace, cid.Undef, cid.Undef, arcset.NewSetFrom(map[string]cid.Cid{
				layout.NodeSlotPath(childRoot, 1).String(): corruptValue,
			})); err != nil {
				t.Fatalf("failed to corrupt child materialization: %v", err)
			}

			if _, err := semantic.Replace(ctx, namespace, root, uint64(branching), values[branching], newPayloadCID([]byte("replacement"))); err == nil {
				t.Fatal("Replace should reject corrupted child materialization")
			}
		})
	}
}

func TestMutationRejectsLegacyRootBeforePartialVersionUpgrade(t *testing.T) {
	ctx := context.Background()
	scheme, err := ipa.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	store := materialmemory.New(true)
	legacy, err := tree.NewListForVersion(scheme, store, maltcid.LegacyMALTVersionID)
	if err != nil {
		t.Fatal(err)
	}
	current, err := tree.NewList(scheme, store)
	if err != nil {
		t.Fatal(err)
	}
	geometry := geometryForScheme(t, scheme)
	values := makeValues(geometry.ListBranchingFactor() + 1)
	root, err := legacy.Commit(ctx, "legacy-deep-list", list.NewViewFromSlice(values))
	if err != nil {
		t.Fatal(err)
	}
	if maltcid.VersionIDOf(root) != maltcid.LegacyMALTVersionID {
		t.Fatal("fixture did not produce a v2 list root")
	}
	assertRejected := func(operation string, err error) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), "cannot be mutated") {
			t.Fatalf("%s legacy root error = %v", operation, err)
		}
	}
	_, err = current.Replace(ctx, "legacy-deep-list", root, uint64(len(values)-1), values[len(values)-1], newPayloadCID([]byte("replacement")))
	assertRejected("Replace", err)
	_, _, err = current.Append(ctx, "legacy-deep-list", root, newPayloadCID([]byte("append")))
	assertRejected("Append", err)
	_, err = current.Truncate(ctx, "legacy-deep-list", root, uint64(len(values)-1))
	assertRejected("Truncate", err)

	fixedRoot, err := legacy.CommitFixed(ctx, "legacy-fixed-list", values[:2], 4, 8)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = current.AppendFixed(ctx, "legacy-fixed-list", fixedRoot, newPayloadCID([]byte("fixed-append")), 12)
	assertRejected("AppendFixed", err)
}

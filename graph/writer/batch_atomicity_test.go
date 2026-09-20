package writer

import (
	"context"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	materialmemory "github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment/kzg"
	semanticmapping "github.com/dewebprotocol/malt-core/auth/semantic/mapping"
	"github.com/dewebprotocol/malt-core/auth/semantic/mapping/radix"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

// TestSemanticBatchUpdate_MidBatchFailure tests the deferred persistence path in
// semantic.BatchUpdate: if the second update in a batch fails, the first update's
// changes must NOT be persisted (P2 regression guard).
func TestSemanticBatchUpdate_MidBatchFailure(t *testing.T) {
	ctx := context.Background()
	namespace := "test-mid-batch"

	store := materialmemory.New(true)
	scheme, err := kzg.NewScheme()
	if err != nil {
		t.Fatalf("NewScheme: %v", err)
	}
	maps, err := radix.NewMap(scheme, store)
	if err != nil {
		t.Fatalf("NewMap: %v", err)
	}

	// Commit initial state: key-a and key-b
	valueA := makeCID(t, "value-a")
	valueB := makeCID(t, "value-b")
	root, err := maps.Commit(ctx, namespace, semanticmapping.NewViewFrom(map[string]cid.Cid{
		"key-a": valueA,
		"key-b": valueB,
	}))
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// Determine the intermediate root CID (state after inserting key-new alongside key-a/key-b).
	// Commit to a probe namespace: CID is content-addressed so it equals what loop-Update
	// would produce in the main namespace, but data goes to the probe namespace only.
	valueNew := makeCID(t, "value-new")
	intermediateRoot, err := maps.Commit(ctx, namespace+"_probe", semanticmapping.NewViewFrom(map[string]cid.Cid{
		"key-a":   valueA,
		"key-b":   valueB,
		"key-new": valueNew,
	}))
	if err != nil {
		t.Fatalf("probe Commit: %v", err)
	}

	// Batch: first op inserts key-new (valid), second op uses wrong OldValue (fails)
	wrongOld := makeCID(t, "wrong-old")
	_, err = maps.BatchUpdate(ctx, namespace, root, []semanticmapping.BatchUpdate{
		{Key: arcset.CanonicalizePath("key-new"), OldValue: cid.Undef, NewValue: valueNew},
		{Key: arcset.CanonicalizePath("key-a"), OldValue: wrongOld, NewValue: makeCID(t, "value-x")},
	})
	if err == nil {
		t.Fatal("BatchUpdate should have failed due to OldValue mismatch, but succeeded")
	}
	t.Logf("BatchUpdate correctly failed: %v", err)

	// Regression guard: if BatchUpdate regresses to loop-calling Update, the intermediate
	// root's node data gets written to the main namespace before the second update fails.
	// Verify the intermediate root is NOT readable in the main namespace.
	_, _, err = maps.Prove(ctx, namespace, intermediateRoot, arcset.CanonicalizePath("key-new"))
	if err == nil {
		t.Error("atomicity violated: intermediate root was persisted in main namespace during failed batch")
	}

	// key-new must NOT be findable under the original root either.
	absent, _, err := maps.Prove(ctx, namespace, root, arcset.CanonicalizePath("key-new"))
	if err != nil || absent.Present {
		t.Errorf("atomicity violated: key-new absence = %+v, %v", absent, err)
	}

	// key-a must still have original value
	bindingA, _, err := maps.Prove(ctx, namespace, root, arcset.CanonicalizePath("key-a"))
	if err != nil {
		t.Fatalf("Prove(key-a): %v", err)
	}
	if !bindingA.Value.Equals(valueA) {
		t.Errorf("atomicity violated: key-a = %v, want original %v", bindingA.Value, valueA)
	}
}

func makeCID(t *testing.T, data string) cid.Cid {
	t.Helper()
	mhash, err := mh.Sum([]byte(data), mh.SHA2_256, -1)
	if err != nil {
		t.Fatalf("Build CID failed: %v", err)
	}
	return cid.NewCidV1(cid.Raw, mhash)
}

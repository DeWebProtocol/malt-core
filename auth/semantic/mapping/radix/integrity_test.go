package radix_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	materialmemory "github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment/kzg"
	"github.com/dewebprotocol/malt-core/auth/semantic/mapping"
	mappingradix "github.com/dewebprotocol/malt-core/auth/semantic/mapping/radix"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

// TestUpdateRejectsCorruptedNode verifies that Update and BatchUpdate reject
// operations when persisted node data has been corrupted (P1 security issue).
func TestUpdateRejectsCorruptedNode(t *testing.T) {
	ctx := context.Background()
	namespace := "test"

	// Setup
	store := materialmemory.New(true)
	scheme, err := kzg.NewScheme()
	if err != nil {
		t.Fatalf("NewScheme failed: %v", err)
	}
	maps, err := mappingradix.NewMap(scheme, store)
	if err != nil {
		t.Fatalf("NewMap failed: %v", err)
	}

	// Create initial structure with a few keys
	valueA := makeCID(t, "value-a")
	valueB := makeCID(t, "value-b")

	initialView := mapping.NewViewFrom(map[string]cid.Cid{
		"key-a": valueA,
		"key-b": valueB,
	})
	root, err := maps.Commit(ctx, namespace, initialView)
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	// Verify we can read the values
	binding, _, err := maps.Prove(ctx, namespace, root, arcset.CanonicalizePath("key-a"))
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}
	if !binding.Value.Equals(valueA) {
		t.Errorf("Expected value-a, got %v", binding.Value)
	}

	// Now corrupt the node data by modifying a slot in ArcSet materializer
	// We'll corrupt the first slot of the root node
	corruptValue := makeCID(t, "corrupted-data")
	corruptPath := arcset.CanonicalizePath(fmt.Sprintf("runtime/map/radix/nodes/%s/slots/0", root.String()))
	corruptArcs, err := arcset.NewArcSetFromPaths(map[arcset.Path]cid.Cid{
		corruptPath: corruptValue,
	})
	if err != nil {
		t.Fatalf("Failed to create corrupt arcset: %v", err)
	}
	err = store.Update(ctx, namespace, cid.Undef, cid.Undef, corruptArcs)
	if err != nil {
		t.Fatalf("Failed to corrupt node: %v", err)
	}

	// Test 1: Update should reject the corrupted root
	newValueC := makeCID(t, "value-c")
	_, err = maps.Update(ctx, namespace, root, arcset.CanonicalizePath("key-c"), cid.Undef, newValueC)
	if err == nil {
		t.Errorf("Update should have rejected corrupted node, but succeeded")
	} else if expected := "materialized node state does not match root " + root.String(); err.Error() != expected {
		t.Errorf("Update rejected with unexpected error: %v", err)
	}

	// Test 2: BatchUpdate should also reject the corrupted root
	updates := []mapping.BatchUpdate{
		{Key: arcset.CanonicalizePath("key-d"), OldValue: cid.Undef, NewValue: makeCID(t, "value-d")},
		{Key: arcset.CanonicalizePath("key-e"), OldValue: cid.Undef, NewValue: makeCID(t, "value-e")},
	}
	_, err = maps.BatchUpdate(ctx, namespace, root, updates)
	if err == nil {
		t.Errorf("BatchUpdate should have rejected corrupted node, but succeeded")
	} else if expected := "materialized node state does not match root " + root.String(); err.Error() != expected {
		t.Errorf("BatchUpdate rejected with unexpected error: %v", err)
	}

	t.Log("P1 fix verified: corrupted nodes are correctly rejected")
}

func makeCID(t *testing.T, data string) cid.Cid {
	t.Helper()
	mhash, err := mh.Sum([]byte(data), mh.SHA2_256, -1)
	if err != nil {
		t.Fatalf("Build CID failed: %v", err)
	}
	return cid.NewCidV1(cid.Raw, mhash)
}

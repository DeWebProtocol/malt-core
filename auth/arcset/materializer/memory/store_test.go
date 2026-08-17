package memory

import (
	"context"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

func TestStorePreservesBranchSnapshots(t *testing.T) {
	store := New(true)
	rootA := testCID(t, "a")
	rootB := testCID(t, "b")
	target := testCID(t, "target")
	if err := store.Update(context.Background(), "test", rootA, cid.Undef, arcset.NewSetFrom(map[string]cid.Cid{"a": target})); err != nil {
		t.Fatal(err)
	}
	if err := store.Update(context.Background(), "test", rootB, rootA, arcset.NewSetFrom(map[string]cid.Cid{"b": target})); err != nil {
		t.Fatal(err)
	}
	first, err := store.Snapshot(context.Background(), "test", rootA)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := first.Get(arcset.Path("b")); ok {
		t.Fatal("child update changed parent snapshot")
	}
}

func TestStoreRetainRootsPrunesBranchesAndPreservesReachableNodes(t *testing.T) {
	store := New(true)
	child := testCID(t, "child")
	kept := testCID(t, "kept")
	discarded := testCID(t, "discarded")
	other := testCID(t, "other")
	target := testCID(t, "target")
	if err := store.UpdateNode(context.Background(), "scope", child, arcset.NewSetFrom(map[string]cid.Cid{"node/child": target})); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateNode(context.Background(), "scope", discarded, arcset.NewSetFrom(map[string]cid.Cid{"node/discarded": target})); err != nil {
		t.Fatal(err)
	}
	if err := store.Update(context.Background(), "scope", child, cid.Undef, arcset.NewSetFrom(map[string]cid.Cid{"leaf": target})); err != nil {
		t.Fatal(err)
	}
	if err := store.Update(context.Background(), "scope", kept, cid.Undef, arcset.NewSetFrom(map[string]cid.Cid{"child": child})); err != nil {
		t.Fatal(err)
	}
	if err := store.Update(context.Background(), "scope", discarded, cid.Undef, arcset.NewSetFrom(map[string]cid.Cid{"discarded": target})); err != nil {
		t.Fatal(err)
	}
	if err := store.Update(context.Background(), "other", other, cid.Undef, arcset.NewSetFrom(map[string]cid.Cid{"other": target})); err != nil {
		t.Fatal(err)
	}

	if removed := store.RetainRoots(map[string][]cid.Cid{"scope": {kept}}); removed != 3 {
		t.Fatalf("removed %d roots/node roots, want 3", removed)
	}
	if got := store.RootCount(); got != 2 {
		t.Fatalf("retained %d roots, want kept root and reachable child", got)
	}
	if _, err := store.Snapshot(context.Background(), "scope", child); err != nil {
		t.Fatalf("reachable child was removed: %v", err)
	}
	if _, err := store.Snapshot(context.Background(), "scope", discarded); err == nil {
		t.Fatal("discarded branch remains materialized")
	}
	if _, err := store.Snapshot(context.Background(), "other", other); err == nil {
		t.Fatal("unretained scope remains materialized")
	}
	if _, err := store.Get(context.Background(), "scope", cid.Undef, "node/child"); err != nil {
		t.Fatalf("reachable node cache was removed: %v", err)
	}
	if _, err := store.Get(context.Background(), "scope", cid.Undef, "node/discarded"); err == nil {
		t.Fatal("discarded node cache remains materialized")
	}
}

func testCID(t *testing.T, seed string) cid.Cid {
	t.Helper()
	hash, err := mh.Sum([]byte(seed), mh.SHA2_256, -1)
	if err != nil {
		t.Fatal(err)
	}
	return cid.NewCidV1(cid.Raw, hash)
}

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
	if err := store.Update(context.Background(), "test", rootA, cid.Undef, checkedArcSet(map[string]cid.Cid{"a": target})); err != nil {
		t.Fatal(err)
	}
	if err := store.Update(context.Background(), "test", rootB, rootA, checkedArcSet(map[string]cid.Cid{"b": target})); err != nil {
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

func testCID(t *testing.T, seed string) cid.Cid {
	t.Helper()
	hash, err := mh.Sum([]byte(seed), mh.SHA2_256, -1)
	if err != nil {
		t.Fatal(err)
	}
	return cid.NewCidV1(cid.Raw, hash)
}

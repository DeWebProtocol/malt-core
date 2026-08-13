package radix

import (
	"context"
	"fmt"
	"testing"

	"github.com/dewebprotocol/malt/auth/arcset"
	materialmemory "github.com/dewebprotocol/malt/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt/auth/commitment"
	"github.com/dewebprotocol/malt/auth/commitment/kzg"
	"github.com/dewebprotocol/malt/auth/semantic/mapping"
	cid "github.com/ipfs/go-cid"
	"github.com/multiformats/go-multihash"
)

func TestBatchUpdateCommitsFinalRootOnceAndMatchesSequentialUpdates(t *testing.T) {
	ctx := context.Background()
	baseScheme, err := kzg.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	counting := &commitCountingRootScheme{
		IndexCommitment: baseScheme,
		rootProver:      baseScheme,
	}
	batched, err := NewMap(counting, materialmemory.New(true))
	if err != nil {
		t.Fatal(err)
	}
	sequential, err := NewMap(baseScheme, materialmemory.New(true))
	if err != nil {
		t.Fatal(err)
	}

	keys := []arcset.Path{arcset.CanonicalizePath("alpha"), arcset.CanonicalizePath("beta")}
	firstDigest := hashPath(keys[0])
	secondDigest := hashPath(keys[1])
	firstSlot, firstOK := batched.geometry.MapDigit(firstDigest[:], 0)
	secondSlot, secondOK := batched.geometry.MapDigit(secondDigest[:], 0)
	if !firstOK || !secondOK || firstSlot == secondSlot {
		t.Fatalf("test keys do not occupy distinct root slots: %d, %d", firstSlot, secondSlot)
	}
	oldValues := []cid.Cid{batchUpdateCID(t, "old-alpha"), batchUpdateCID(t, "old-beta")}
	newValues := []cid.Cid{batchUpdateCID(t, "new-alpha"), batchUpdateCID(t, "new-beta")}
	initial := mapping.NewViewFromPaths(map[arcset.Path]cid.Cid{
		keys[0]: oldValues[0],
		keys[1]: oldValues[1],
	})
	batchRoot, err := batched.Commit(ctx, "batch", initial)
	if err != nil {
		t.Fatal(err)
	}
	sequentialRoot, err := sequential.Commit(ctx, "sequential", initial)
	if err != nil {
		t.Fatal(err)
	}
	if !batchRoot.Equals(sequentialRoot) {
		t.Fatalf("initial roots differ: %s != %s", batchRoot, sequentialRoot)
	}

	counting.commits = 0
	batchRoot, err = batched.BatchUpdate(ctx, "batch", batchRoot, []mapping.BatchUpdate{
		{Key: keys[0], OldValue: oldValues[0], NewValue: newValues[0]},
		{Key: keys[1], OldValue: oldValues[1], NewValue: newValues[1]},
	})
	if err != nil {
		t.Fatal(err)
	}
	if counting.commits != 1 {
		t.Fatalf("batch commitment calls = %d, want one final root commitment", counting.commits)
	}
	for index := range keys {
		sequentialRoot, err = sequential.Update(
			ctx,
			"sequential",
			sequentialRoot,
			keys[index],
			oldValues[index],
			newValues[index],
		)
		if err != nil {
			t.Fatal(err)
		}
	}
	if !batchRoot.Equals(sequentialRoot) {
		t.Fatalf("batch root = %s, sequential root = %s", batchRoot, sequentialRoot)
	}
}

func TestBatchUpdateMatchesSequentialUpdatesWithinOneRootSlot(t *testing.T) {
	ctx := context.Background()
	scheme, err := kzg.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	batched, err := NewMap(scheme, materialmemory.New(true))
	if err != nil {
		t.Fatal(err)
	}
	sequential, err := NewMap(scheme, materialmemory.New(true))
	if err != nil {
		t.Fatal(err)
	}

	keys := sameRootSlotPaths(t, batched)
	oldValues := []cid.Cid{batchUpdateCID(t, "old-collision-a"), batchUpdateCID(t, "old-collision-b")}
	newValues := []cid.Cid{batchUpdateCID(t, "new-collision-a"), batchUpdateCID(t, "new-collision-b")}
	initial := mapping.NewViewFromPaths(map[arcset.Path]cid.Cid{
		keys[0]: oldValues[0],
		keys[1]: oldValues[1],
	})
	batchRoot, err := batched.Commit(ctx, "batch-collision", initial)
	if err != nil {
		t.Fatal(err)
	}
	sequentialRoot, err := sequential.Commit(ctx, "sequential-collision", initial)
	if err != nil {
		t.Fatal(err)
	}

	batchRoot, err = batched.BatchUpdate(ctx, "batch-collision", batchRoot, []mapping.BatchUpdate{
		{Key: keys[0], OldValue: oldValues[0], NewValue: newValues[0]},
		{Key: keys[1], OldValue: oldValues[1], NewValue: newValues[1]},
	})
	if err != nil {
		t.Fatal(err)
	}
	for index := range keys {
		sequentialRoot, err = sequential.Update(
			ctx,
			"sequential-collision",
			sequentialRoot,
			keys[index],
			oldValues[index],
			newValues[index],
		)
		if err != nil {
			t.Fatal(err)
		}
	}
	if !batchRoot.Equals(sequentialRoot) {
		t.Fatalf("same-slot batch root = %s, sequential root = %s", batchRoot, sequentialRoot)
	}
	for index, key := range keys {
		got, _, err := batched.Prove(ctx, "batch-collision", batchRoot, key)
		if err != nil {
			t.Fatal(err)
		}
		if !got.Present || !got.Value.Equals(newValues[index]) {
			t.Fatalf("Prove(%s) = %+v, want %s", key, got, newValues[index])
		}
	}
}

func sameRootSlotPaths(t *testing.T, value *Map) []arcset.Path {
	t.Helper()
	bySlot := make(map[uint64]arcset.Path)
	for index := 0; index < 1<<16; index++ {
		candidate := arcset.CanonicalizePath(fmt.Sprintf("collision-%d", index))
		digest := hashPath(candidate)
		slot, ok := value.geometry.MapDigit(digest[:], 0)
		if !ok {
			t.Fatal("map geometry has no root digit")
		}
		if previous, exists := bySlot[slot]; exists {
			return []arcset.Path{previous, candidate}
		}
		bySlot[slot] = candidate
	}
	t.Fatal("failed to find two paths in one root slot")
	return nil
}

func batchUpdateCID(t *testing.T, value string) cid.Cid {
	t.Helper()
	digest, err := multihash.Sum([]byte(value), multihash.SHA2_256, -1)
	if err != nil {
		t.Fatal(err)
	}
	return cid.NewCidV1(cid.Raw, digest)
}

var _ commitment.IndexCommitment = (*commitCountingRootScheme)(nil)

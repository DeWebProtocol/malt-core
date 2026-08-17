package radix

import (
	"context"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

func TestBucketEntriesRemainReachableThroughEncodedReference(t *testing.T) {
	ctx := context.Background()
	const namespace = "radix-bucket-retention"

	store := memory.New(true)
	semantic := &Map{materializer: store}
	parentRoot := retentionTestCID(t, "parent")
	bucketRoot := retentionTestCID(t, "bucket")
	markers := []cid.Cid{
		retentionTestCID(t, "first-marker"),
		retentionTestCID(t, "second-marker"),
	}
	bucketRef, err := encodeBucketRef(bucketRoot)
	if err != nil {
		t.Fatalf("encodeBucketRef failed: %v", err)
	}

	if err := semantic.storeBucketEntries(ctx, namespace, bucketRoot, markers); err != nil {
		t.Fatalf("storeBucketEntries failed: %v", err)
	}
	if err := semantic.storeNodeSlots(ctx, namespace, parentRoot, []cid.Cid{bucketRef}); err != nil {
		t.Fatalf("storeNodeSlots failed: %v", err)
	}

	if removed := store.RetainRoots(map[string][]cid.Cid{namespace: {parentRoot}}); removed != 0 {
		t.Fatalf("RetainRoots removed %d reachable node roots, want 0", removed)
	}

	got, err := semantic.loadBucketEntries(ctx, namespace, bucketRoot)
	if err != nil {
		t.Fatalf("loadBucketEntries after RetainRoots failed: %v", err)
	}
	if len(got) != len(markers) {
		t.Fatalf("loaded %d bucket entries, want %d", len(got), len(markers))
	}
	for i := range markers {
		if !got[i].Equals(markers[i]) {
			t.Fatalf("bucket entry %d = %s, want %s", i, got[i], markers[i])
		}
	}
}

func retentionTestCID(t *testing.T, seed string) cid.Cid {
	t.Helper()
	hash, err := mh.Sum([]byte(seed), mh.SHA2_256, -1)
	if err != nil {
		t.Fatalf("hashing test CID: %v", err)
	}
	return cid.NewCidV1(cid.Raw, hash)
}

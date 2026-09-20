package memory

import (
	"context"
	"github.com/dewebprotocol/malt-core/auth/arcset"
	cid "github.com/ipfs/go-cid"
	"testing"
)

func TestUpdateNodeRejectsSecondOwnerWithoutMutatingState(t *testing.T) {
	ctx := context.Background()
	store := New(true)
	firstRoot := testCID(t, "first-node-root")
	secondRoot := testCID(t, "second-node-root")
	firstTarget := testCID(t, "first-node-target")
	secondTarget := testCID(t, "second-node-target")
	path := "runtime/nodes/shared"
	if err := store.UpdateNode(ctx, "scope", firstRoot, checkedArcSet(map[string]cid.Cid{
		path: firstTarget,
	})); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateNode(ctx, "scope", secondRoot, checkedArcSet(map[string]cid.Cid{
		path: secondTarget,
	})); err == nil {
		t.Fatal("a second node-root owner was accepted")
	}
	if got, err := store.Get(ctx, "scope", cid.Undef, arcset.Path(path)); err != nil || !got.Equals(firstTarget) {
		t.Fatalf("first owner changed after rejected update: got %s, err %v", got, err)
	}
	if err := store.UpdateNode(ctx, "scope", secondRoot, checkedArcSet(map[string]cid.Cid{
		path: cid.Undef,
	})); err != nil {
		t.Fatal(err)
	}
	if got, err := store.Get(ctx, "scope", cid.Undef, arcset.Path(path)); err != nil || !got.Equals(firstTarget) {
		t.Fatalf("non-owner delete changed first owner: got %s, err %v", got, err)
	}
	if owner := store.scopes["scope"].nodeOwners[arcset.Path(path)]; owner != firstRoot.KeyString() {
		t.Fatalf("node owner = %q, want %q", owner, firstRoot.KeyString())
	}
}

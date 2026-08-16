package memory

import (
	"context"
	"reflect"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	cid "github.com/ipfs/go-cid"
)

func TestStateRoundTripPreservesRootsAndNodeOwnership(t *testing.T) {
	ctx := context.Background()
	store := New(true)
	root := testCID(t, "root")
	nodeRoot := testCID(t, "node-root")
	target := testCID(t, "target")
	if err := store.Update(ctx, "scope", root, cid.Undef, arcset.NewSetFrom(map[string]cid.Cid{
		"payload": target,
	})); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateNode(ctx, "scope", nodeRoot, arcset.NewSetFrom(map[string]cid.Cid{
		"runtime/nodes/slot/7": target,
	})); err != nil {
		t.Fatal(err)
	}

	exported, err := store.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := NewFromState(exported)
	if err != nil {
		t.Fatal(err)
	}
	next, err := restored.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(next, exported) {
		t.Fatalf("restored state differs:\n got: %#v\nwant: %#v", next, exported)
	}
	if got, err := restored.Get(ctx, "scope", root, "payload"); err != nil || !got.Equals(target) {
		t.Fatalf("restored logical arc = %s, %v", got, err)
	}
	if got, err := restored.Get(ctx, "scope", cid.Undef, "runtime/nodes/slot/7"); err != nil || !got.Equals(target) {
		t.Fatalf("restored node arc = %s, %v", got, err)
	}
	if owner := restored.scopes["scope"].nodeOwners["runtime/nodes/slot/7"]; owner != nodeRoot.KeyString() {
		t.Fatalf("restored node owner = %q, want %q", owner, nodeRoot.KeyString())
	}
}

func TestStateRoundTripPreservesNonBranchingMode(t *testing.T) {
	ctx := context.Background()
	store := New(false)
	root := testCID(t, "non-branching-root")
	target := testCID(t, "non-branching-target")
	if err := store.Update(ctx, "scope", root, cid.Undef, arcset.NewSetFrom(map[string]cid.Cid{
		"payload": target,
	})); err != nil {
		t.Fatal(err)
	}
	exported, err := store.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := NewFromState(exported)
	if err != nil {
		t.Fatal(err)
	}
	if restored.SupportsConcurrentBranches() {
		t.Fatal("restored non-branching materializer unexpectedly supports concurrent branches")
	}
	next, err := restored.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(next, exported) {
		t.Fatalf("restored non-branching state differs:\n got: %#v\nwant: %#v", next, exported)
	}
}

func TestUpdateNodeRejectsSecondOwnerWithoutMutatingState(t *testing.T) {
	ctx := context.Background()
	store := New(true)
	firstRoot := testCID(t, "first-node-root")
	secondRoot := testCID(t, "second-node-root")
	firstTarget := testCID(t, "first-node-target")
	secondTarget := testCID(t, "second-node-target")
	path := "runtime/nodes/shared"
	if err := store.UpdateNode(ctx, "scope", firstRoot, arcset.NewSetFrom(map[string]cid.Cid{
		path: firstTarget,
	})); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateNode(ctx, "scope", secondRoot, arcset.NewSetFrom(map[string]cid.Cid{
		path: secondTarget,
	})); err == nil {
		t.Fatal("a second node-root owner was accepted")
	}
	if got, err := store.Get(ctx, "scope", cid.Undef, arcset.Path(path)); err != nil || !got.Equals(firstTarget) {
		t.Fatalf("first owner changed after rejected update: got %s, err %v", got, err)
	}
	if err := store.UpdateNode(ctx, "scope", secondRoot, arcset.NewSetFrom(map[string]cid.Cid{
		path: cid.Undef,
	})); err != nil {
		t.Fatal(err)
	}
	if got, err := store.Get(ctx, "scope", cid.Undef, arcset.Path(path)); err != nil || !got.Equals(firstTarget) {
		t.Fatalf("non-owner delete changed first owner: got %s, err %v", got, err)
	}
	exported, err := store.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := NewFromState(exported)
	if err != nil {
		t.Fatalf("state after rejected second owner is not restorable: %v", err)
	}
	if owner := restored.scopes["scope"].nodeOwners[arcset.Path(path)]; owner != firstRoot.KeyString() {
		t.Fatalf("restored node owner = %q, want %q", owner, firstRoot.KeyString())
	}
}

func TestNewFromStateRejectsUnauthenticatableShape(t *testing.T) {
	target := testCID(t, "target")
	_, err := NewFromState(State{
		Branching: true,
		Scopes: []ScopeState{{
			Scope: "scope",
			Nodes: []Entry{{Path: "node/path", Target: target}},
		}},
	})
	if err == nil {
		t.Fatal("state with an unowned node path was accepted")
	}
}

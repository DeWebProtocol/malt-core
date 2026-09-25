package object_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/coordinate"
	"github.com/dewebprotocol/malt-core/maltcid"
	"github.com/dewebprotocol/malt-core/sdk/authentication/builtin"
	"github.com/dewebprotocol/malt-core/sdk/object"
	"github.com/dewebprotocol/malt-core/traversal"
	cid "github.com/ipfs/go-cid"
)

func TestListReferenceOperations(t *testing.T) {
	l, err := object.NewList(engineFor(t), object.ListConfig(maltcid.IPA256))
	must(t, err)
	one, two, three := leaf(t, "one"), leaf(t, "two"), leaf(t, "three")
	items := []object.Object{one, two}
	must(t, l.Append(items...))
	items[0] = three
	if got, err := l.Get(0); err != nil || got != one {
		t.Fatal("Append borrowed the caller's slice")
	}
	if err := l.Append(three, (*object.Map)(nil)); err == nil || l.Len() != 2 {
		t.Fatal("failed Append changed the List")
	}
	if err := l.Set(0, nil); err == nil {
		t.Fatal("Set accepted nil")
	}
	must(t, l.Set(0, three))
	must(t, l.Remove(0))
	if got, err := l.Get(0); err != nil || got != two || l.Len() != 1 {
		t.Fatal("Remove did not shift the remaining reference")
	}
	for _, index := range []int{-1, 1, 100} {
		if _, err := l.Get(index); err == nil {
			t.Fatalf("Get accepted index %d", index)
		}
		if l.Set(index, one) == nil || l.Remove(index) == nil {
			t.Fatalf("mutation accepted index %d", index)
		}
	}
	if _, err := object.NewList(engineFor(t), object.MapConfig(maltcid.IPA256)); err == nil {
		t.Fatal("List accepted Prefix")
	}
}

func TestListCommitsDenseIndicesWithBothBackends(t *testing.T) {
	for _, profile := range []maltcid.ProfileID{maltcid.IPA256, maltcid.KZG4096} {
		t.Run(fmt.Sprint(profile), func(t *testing.T) {
			l, err := object.NewList(engineFor(t), object.ListConfig(profile))
			must(t, err)
			empty := commit(t, l)
			if l.Payload().Defined() {
				t.Fatal("plain List has an unexpected payload")
			}
			one, two, three := leaf(t, "one"), leaf(t, "two"), leaf(t, "three")
			must(t, l.Append(one, two))
			commit(t, l)
			old := retained(t, l)
			must(t, l.Set(0, three))
			must(t, l.Append(one))
			must(t, l.Remove(1))
			commit(t, l)
			checkBinding(t, old, coordinate.EncodeIndex(0), one.Payload())
			checkBinding(t, old, coordinate.EncodeIndex(1), two.Payload())
			checkBinding(t, retained(t, l), coordinate.EncodeIndex(0), three.Payload())
			checkBinding(t, retained(t, l), coordinate.EncodeIndex(1), one.Payload())
			checkBinding(t, retained(t, l), coordinate.EncodeIndex(2), cid.Undef)
			must(t, l.Remove(0))
			must(t, l.Remove(0))
			if !commit(t, l).Equals(empty) {
				t.Fatal("removing all items did not reproduce the empty List Root")
			}
		})
	}
}

func TestMixedObjectGraphTraversalAndCycles(t *testing.T) {
	ctx := context.Background()
	parent, child := mapFor(t), mapFor(t)
	l, err := object.NewList(engineFor(t), object.ListConfig(maltcid.KZG4096))
	must(t, err)
	data := leaf(t, "mixed graph")
	must(t, child.Set([]byte("data"), data))
	must(t, l.Append(child))
	must(t, parent.Set([]byte("items"), l))
	root := commit(t, parent)
	nodes := materialize(t, retained(t, child), retained(t, l), retained(t, parent))
	steps := [][]byte{[]byte("items"), coordinate.EncodeIndex(0), []byte("data")}
	target, proof, err := traversal.ResolvePath(ctx, engineFor(t), root, steps, nodes)
	must(t, err)
	verifier, err := builtin.NewVerifier()
	must(t, err)
	ok, err := traversal.Verify(verifier, root, steps, target, proof)
	must(t, err)
	if !ok || !target.Equals(data.Payload()) {
		t.Fatal("mixed Map/List/Immutable traversal did not verify")
	}
	must(t, child.Set([]byte("back"), l))
	if _, err := parent.Commit(ctx); !errors.Is(err, object.ErrCycle) {
		t.Fatalf("Map/List cycle: %v", err)
	}
	child.Delete([]byte("back"))
	must(t, l.Append(l))
	if _, err := l.Commit(ctx); !errors.Is(err, object.ErrCycle) {
		t.Fatalf("List self-cycle: %v", err)
	}
}

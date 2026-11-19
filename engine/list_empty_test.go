package engine_test

import (
	"fmt"
	"math"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/coordinate"
	"github.com/dewebprotocol/malt-core/derivation"
	"github.com/dewebprotocol/malt-core/engine"
	"github.com/dewebprotocol/malt-core/maltcid"
	cid "github.com/ipfs/go-cid"
)

func TestListEmptyCells(t *testing.T) {
	for _, profile := range []maltcid.ProfileID{maltcid.IPA256, maltcid.KZG4096} {
		t.Run(fmt.Sprint(profile), func(t *testing.T) {
			e, nodes := setup(t, profile)
			ctx := t.Context()
			p, _ := maltcid.Profile(profile)
			width := uint64(p.Slots)
			state := engine.State{Descriptor: maltcid.RootDescriptor{Layout: maltcid.List, DerivationProfile: uint8(derivation.Direct), Profile: profile}, PayloadCID: target("metadata")}
			value := cid.MustParse("bafkqaaa")
			build := func(indices ...uint64) cid.Cid {
				t.Helper()
				s := state
				for _, i := range indices {
					s.Entries = append(s.Entries, engine.Entry{Label: coordinate.EncodeIndex(i), Target: value})
				}
				root, err := e.Build(ctx, s, nodes)
				if err != nil {
					t.Fatal(err)
				}
				return root
			}
			root := build(2*width, 0, 2)
			view, err := e.SnapshotBounded(ctx, root, nodes, 3)
			if err != nil || len(view.Bindings) != 3 || view.Bindings[1].Coordinate.Index != 2 || view.Bindings[2].Coordinate.Index != 2*width {
				t.Fatal("snapshot lost occupied indices", err)
			}
			if _, err := e.SnapshotBounded(ctx, root, nodes, 2); err == nil {
				t.Fatal("snapshot ignored the occupied binding bound")
			}
			for _, tc := range []struct {
				index   uint64
				present bool
				depth   int
			}{
				{0, true, 2}, {1, false, 2}, {width, false, 1}, {2 * width, true, 2}, {2*width + 1, false, 1},
			} {
				label := coordinate.EncodeIndex(tc.index)
				r, err := e.Prove(ctx, root, label, nodes)
				if err != nil || r.Present != tc.present || len(r.Proof.Nodes) != tc.depth {
					t.Fatalf("index %d: present=%v depth=%d err=%v", tc.index, r.Present, len(r.Proof.Nodes), err)
				}
				last := r.Proof.Nodes[tc.depth-1]
				if !tc.present && (len(last.Cell) != 0 || (len(last.Proof) > 0) != (tc.index <= 2*width)) {
					t.Fatalf("incorrect empty cell or length evidence at %d", tc.index)
				}
				if valid, err := e.Verify(root, label, r); err != nil || !valid {
					t.Fatalf("index %d verification: %v", tc.index, err)
				}
				if tc.index == width {
					r.Proof.Nodes[0].Proof = nil
					if valid, _ := e.Verify(root, label, r); valid {
						t.Fatal("metadata alone proved an in-range hole")
					}
				}
			}
			stop := uint64(3)
			r, err := e.ProveRange(ctx, root, 0, &stop, nodes)
			if err != nil || len(r.Segments) != 3 || !r.Segments[0].Present || r.Segments[1].Present || !r.Segments[2].Present {
				t.Fatal("range lost an empty position", err)
			}
			if ok, err := e.VerifyRange(root, 0, &stop, r); err != nil || !ok {
				t.Fatal("verify sparse range", err)
			}
			r.Segments[1] = r.Segments[0]
			if ok, _ := e.VerifyRange(root, 0, &stop, r); ok {
				t.Fatal("accepted substituted segment")
			}

			fill := func(i uint64) engine.Change { return engine.Change{Label: coordinate.EncodeIndex(i), After: value} }
			drop := func(i uint64) engine.Change { return engine.Change{Label: coordinate.EncodeIndex(i), Before: value} }
			apply := func(changes []engine.Change, want ...uint64) {
				t.Helper()
				next, err := e.Apply(ctx, root, changes, nodes, nodes)
				if err != nil || !next.Equals(build(want...)) {
					t.Fatalf("apply %v: %v", want, err)
				}
				root = next
			}
			apply([]engine.Change{fill(1), drop(0), fill(width)}, 1, 2, width, 2*width)
			apply([]engine.Change{drop(width), drop(2 * width)}, 1, 2)
			high := uint64(math.MaxUint64 - 1)
			apply([]engine.Change{fill(high)}, 1, 2, high)
			if _, err := e.ProveRange(ctx, root, 0, nil, nodes); err == nil {
				t.Fatal("unbounded logical range")
			}
			if _, _, err := e.Append(ctx, root, value, nodes, nodes); err == nil {
				t.Fatal("extent overflow")
			}
			if _, err := e.Apply(ctx, root, []engine.Change{fill(math.MaxUint64)}, nodes, nodes); err == nil {
				t.Fatal("accepted maximum uint64 index")
			}
			if _, err := e.Apply(ctx, root, []engine.Change{drop(0)}, nodes, nodes); err == nil {
				t.Fatal("cleared a missing expected target")
			}
			next, err := e.Truncate(ctx, root, width, nodes, nodes)
			if err != nil || !next.Equals(build(1, 2)) {
				t.Fatal("truncation inside gap", err)
			}
			next, first, err := e.Append(ctx, next, value, nodes, nodes)
			if err != nil || first != 3 || !next.Equals(build(1, 2, 3)) {
				t.Fatal("append after gap", first, err)
			}
			apply([]engine.Change{drop(high), drop(1), drop(2)})
			onlyFar := build(2 * width)
			next, err = e.Truncate(ctx, onlyFar, width+1, nodes, nodes)
			if err != nil || !next.Equals(build()) {
				t.Fatal("cut before first binding", err)
			}
		})
	}
}

func TestListPromotionWritesOnlyReachableVectors(t *testing.T) {
	e, base := setup(t, maltcid.IPA256)
	ctx := t.Context()
	state := engine.State{Descriptor: maltcid.RootDescriptor{Layout: maltcid.List, DerivationProfile: uint8(derivation.Direct), Profile: maltcid.IPA256}}
	for i := range 256 {
		state.Entries = append(state.Entries, engine.Entry{Label: coordinate.EncodeIndex(uint64(i)), Target: target("item")})
	}
	root, err := e.Build(ctx, state, base)
	if err != nil {
		t.Fatal(err)
	}
	nodes := &countedNodes{Nodes: base}
	next, err := e.Truncate(ctx, root, 255, nodes, nodes)
	if err != nil || nodes.writes != 1 {
		t.Fatalf("truncation wrote %d vectors: %v", nodes.writes, err)
	}
	nodes.writes = 0
	removed, err := e.Apply(ctx, root, []engine.Change{{Label: coordinate.EncodeIndex(255), Before: target("item")}}, nodes, nodes)
	if err != nil || !removed.Equals(next) || nodes.writes != 1 {
		t.Fatalf("clearing the tail wrote %d vectors: %v", nodes.writes, err)
	}
}

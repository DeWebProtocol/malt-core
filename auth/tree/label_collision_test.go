package tree_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
	"github.com/dewebprotocol/malt-core/auth/coordinate"
	"github.com/dewebprotocol/malt-core/auth/tree"
	"github.com/dewebprotocol/malt-core/maltcid"
	cid "github.com/ipfs/go-cid"
)

// This pure test capability simulates a full-coordinate collision. It does not
// replace SHA256 or introduce a test derivation profile into the public engine.
func collisionCoordinate(_ uint8, label []byte) (coordinate.Coordinate, error) {
	key := [32]byte{1}
	switch string(label) {
	case "peer":
		key[2] = 1
	case "neighbor":
		key[2] = 2
	}
	return coordinate.Coordinate{Kind: coordinate.Key, Key: key}, nil
}

func collisionSelector(label string) tree.Selector {
	k, _ := collisionCoordinate(240, []byte(label))
	return tree.Selector{Coordinate: k, Label: []byte(label)}
}

type countedOutput struct{ calls int }

func (s *countedOutput) PutNode(context.Context, maltcid.NodeRef, []commitment.Cell) error {
	s.calls++
	return nil
}

func TestCoordinateCollisionRejectsBuildProofsAndWrites(t *testing.T) {
	for _, deep := range []bool{false, true} {
		name := "singleton"
		if deep {
			name = "deep"
		}
		t.Run(name, func(t *testing.T) {
			base := newTree(t)
			e := tree.New(base.Profiles, collisionCoordinate)
			nodes := memory.NewNodes()
			d := maltcid.RootDescriptor{Layout: maltcid.Prefix, DerivationProfile: 240, Profile: maltcid.IPA256}
			a, b := collisionSelector("label-a"), collisionSelector("label-b")
			value := cid.MustParse("bafkqaaa")
			state := tree.View{Descriptor: d, Bindings: []tree.CoordinateBinding{{Coordinate: a.Coordinate, Label: a.Label, Target: value}}}
			if deep {
				peer := collisionSelector("peer")
				state.Bindings = append(state.Bindings, tree.CoordinateBinding{Coordinate: peer.Coordinate, Label: peer.Label, Target: value})
			}
			root, err := e.Commit(t.Context(), state, nodes)
			if err != nil {
				t.Fatal(err)
			}
			proof, err := e.Prove(t.Context(), root, a, nodes)
			if err != nil {
				t.Fatal(err)
			}
			if valid, err := e.Verify(root, a, proof); err != nil || !valid {
				t.Fatalf("original label proof: valid=%v err=%v", valid, err)
			}
			if deep && len(proof.Proof.Nodes) < 2 {
				t.Fatal("fixture did not exercise an internal Prefix node")
			}
			if result, err := e.Prove(t.Context(), root, b, nodes); !errors.Is(err, tree.ErrCoordinateCollision) || result.Present || result.Target.Defined() || len(result.Proof.Nodes) != 0 {
				t.Fatalf("collision became a proof: result=%+v err=%v", result, err)
			}
			if valid, err := e.Verify(root, b, proof); valid || !errors.Is(err, tree.ErrCoordinateCollision) {
				t.Fatalf("membership reused for colliding label: valid=%v err=%v", valid, err)
			}
			absence := proof
			absence.Present, absence.Target = false, cid.Undef
			if valid, err := e.Verify(root, b, absence); valid || !errors.Is(err, tree.ErrCoordinateCollision) {
				t.Fatalf("collision became authenticated absence: valid=%v err=%v", valid, err)
			}
			neighbor := collisionSelector("neighbor")
			missing, err := e.Prove(t.Context(), root, neighbor, nodes)
			if err != nil || missing.Present {
				t.Fatalf("ordinary absent coordinate: present=%v err=%v", missing.Present, err)
			}
			if valid, err := e.Verify(root, neighbor, missing); err != nil || !valid {
				t.Fatalf("ordinary absence proof: valid=%v err=%v", valid, err)
			}
			colliding := state
			colliding.Bindings = append(append([]tree.CoordinateBinding{}, state.Bindings...), tree.CoordinateBinding{Coordinate: b.Coordinate, Label: b.Label, Target: value})
			out := &countedOutput{}
			if got, err := e.Commit(t.Context(), colliding, out); got.Defined() || !errors.Is(err, tree.ErrCoordinateCollision) || out.calls != 0 {
				t.Fatalf("collision build published nodes: root=%s calls=%d err=%v", got, out.calls, err)
			}
			for _, changes := range [][]tree.Change{
				{{Coordinate: b.Coordinate, Label: b.Label, After: value}},
				{{Coordinate: b.Coordinate, Label: b.Label, Before: value, After: value}},
				{{Coordinate: b.Coordinate, Label: b.Label, Before: value}},
				{{Coordinate: a.Coordinate, Label: a.Label, Before: value, After: value}, {Coordinate: b.Coordinate, Label: b.Label, After: value}},
			} {
				out := &countedOutput{}
				if got, err := e.Apply(t.Context(), root, changes, nodes, out); got.Defined() || !errors.Is(err, tree.ErrCoordinateCollision) || out.calls != 0 {
					t.Fatalf("collision write published nodes: root=%s calls=%d err=%v", got, out.calls, err)
				}
			}
			_, recovered, err := e.Import(t.Context(), root, nodes, uint64(len(state.Bindings)))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(recovered.Bindings[0].Label, a.Label) {
				t.Fatal("recovery lost original label identity")
			}
			if valid, err := e.Verify(root, a, proof); err != nil || !valid {
				t.Fatal("failed collision write changed the original state", err)
			}
		})
	}
}

func TestSelectorCannotSubstituteRoutingCoordinate(t *testing.T) {
	base := newTree(t)
	e := tree.New(base.Profiles, collisionCoordinate)
	d := maltcid.RootDescriptor{Layout: maltcid.Prefix, DerivationProfile: 240, Profile: maltcid.IPA256}
	q := collisionSelector("label-a")
	wrong := q
	wrong.Coordinate.Key[0] = 2
	value := cid.MustParse("bafkqaaa")
	nodes := memory.NewNodes()
	root, err := e.Commit(t.Context(), tree.View{Descriptor: d, Bindings: []tree.CoordinateBinding{{Coordinate: q.Coordinate, Label: q.Label, Target: value}}}, nodes)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := e.Prove(t.Context(), root, q, nodes)
	if err != nil {
		t.Fatal(err)
	}
	if valid, err := e.Verify(root, wrong, proof); valid || err == nil {
		t.Fatal("caller-selected coordinate bypassed label derivation")
	}
	if _, err := e.Prove(t.Context(), root, wrong, nodes); err == nil {
		t.Fatal("wrong routing coordinate accepted by prover")
	}
	out := &countedOutput{}
	if _, err := e.Commit(t.Context(), tree.View{Descriptor: d, Bindings: []tree.CoordinateBinding{{Coordinate: wrong.Coordinate, Label: q.Label, Target: value}}}, out); err == nil || out.calls != 0 {
		t.Fatal("writer accepted a substituted coordinate")
	}
	if _, err := e.Apply(t.Context(), root, []tree.Change{{Coordinate: wrong.Coordinate, Label: q.Label, Before: value, After: value}}, nodes, out); err == nil || out.calls != 0 {
		t.Fatal("updater accepted a substituted coordinate")
	}
}

func TestCoordinateCollisionRejectsRecoveryAndImport(t *testing.T) {
	base := newTree(t)
	e := tree.New(base.Profiles, collisionCoordinate)
	d := maltcid.RootDescriptor{Layout: maltcid.Prefix, DerivationProfile: 240, Profile: maltcid.IPA256}
	scheme, err := ipa.NewCommitterScheme(ipa.ProfileDirect)
	if err != nil {
		t.Fatal(err)
	}
	cells := make([]commitment.Cell, scheme.MaxValues())
	value := cid.MustParse("bafkqaaa")
	for i, label := range []string{"label-a", "label-b"} {
		cell := binary.AppendUvarint([]byte{maltcid.PrefixLeafCell}, uint64(len(label)))
		cell = append(cell, []byte(label)...)
		cells[i+1] = append(cell, value.Bytes()...)
	}
	// A hostile producer can commit a vector outside the canonical constructor.
	// Recovery must reject its colliding identities instead of indexing/retaining it.
	committed, err := scheme.Commit(cells)
	if err != nil {
		t.Fatal(err)
	}
	data, err := committed.CommitmentBytes(maltcid.IPA256)
	if err != nil {
		t.Fatal(err)
	}
	root, err := maltcid.NewRoot(d, data)
	if err != nil {
		t.Fatal(err)
	}
	ref, _, _ := maltcid.RootNode(root)
	nodes := memory.NewNodes()
	if err := nodes.PutNode(t.Context(), ref, cells); err != nil {
		t.Fatal(err)
	}
	if view, err := e.SnapshotBounded(t.Context(), root, nodes, 2); !errors.Is(err, tree.ErrCoordinateCollision) || len(view.Bindings) != 0 {
		t.Fatalf("recovery accepted colliding labels: view=%+v err=%v", view, err)
	}
	if materialized, _, err := e.Import(t.Context(), root, nodes, 2); !errors.Is(err, tree.ErrCoordinateCollision) || materialized != nil {
		t.Fatalf("import retained colliding labels: materialized=%v err=%v", materialized, err)
	}
}

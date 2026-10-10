package engine_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/dewebprotocol/malt-core/derivation"
	"github.com/dewebprotocol/malt-core/engine"
	"github.com/dewebprotocol/malt-core/maltcid"
)

func TestPrefixLeafAuthenticatesOriginalLabel(t *testing.T) {
	e, nodes := setup(t, maltcid.IPA256)
	label := []byte("original-label-identity")
	value := target("label-bound-target")
	state := engine.State{
		Descriptor: maltcid.RootDescriptor{Layout: maltcid.Prefix, DerivationProfile: uint8(derivation.SHA256), Profile: maltcid.IPA256},
		Entries:    []engine.Entry{{Label: label, Target: value}},
	}
	root, err := e.Build(t.Context(), state, nodes)
	if err != nil {
		t.Fatal(err)
	}
	result, err := e.Prove(t.Context(), root, label, nodes)
	if err != nil {
		t.Fatal(err)
	}
	want := binary.AppendUvarint([]byte{maltcid.PrefixLeafCell}, uint64(len(label)))
	want = append(want, label...)
	want = append(want, value.Bytes()...)
	cell := result.Proof.Nodes[len(result.Proof.Nodes)-1].Cell
	if !bytes.Equal(cell, want) {
		t.Fatalf("leaf does not authenticate the original label: got %x, want %x", cell, want)
	}
	if valid, err := e.Verify(root, label, result); err != nil || !valid {
		t.Fatalf("label-bound proof: valid=%v err=%v", valid, err)
	}
}

func TestPrefixLabelRecoveryPreservesExactBytes(t *testing.T) {
	for _, profile := range []maltcid.ProfileID{maltcid.IPA256, maltcid.KZG4096} {
		t.Run(string(rune(profile+'0')), func(t *testing.T) {
			e, nodes := setup(t, profile)
			d := maltcid.RootDescriptor{Layout: maltcid.Prefix, DerivationProfile: uint8(derivation.SHA256), Profile: profile}
			child, err := e.Build(t.Context(), engine.State{Descriptor: d, Entries: []engine.Entry{{Label: []byte("child"), Target: target("payload")}}}, nodes)
			if err != nil {
				t.Fatal(err)
			}
			labels := [][]byte{{}, {0xff, 0, '/', 0x80}, bytes.Repeat([]byte("long-label"), 30)}
			state := engine.State{Descriptor: d}
			for _, label := range labels {
				state.Entries = append(state.Entries, engine.Entry{Label: label, Target: child})
			}
			root, err := e.Build(t.Context(), state, nodes)
			if err != nil {
				t.Fatal(err)
			}
			for _, label := range labels {
				result, err := e.Prove(t.Context(), root, label, nodes)
				if err != nil {
					t.Fatal(err)
				}
				if valid, err := e.Verify(root, label, result); err != nil || !valid || !result.Target.Equals(child) {
					t.Fatalf("opaque label proof: valid=%v err=%v", valid, err)
				}
			}
			view, err := e.SnapshotBounded(t.Context(), root, nodes, uint64(len(labels)))
			if err != nil {
				t.Fatal(err)
			}
			if err := e.MatchView(state, view); err != nil {
				t.Fatal("recovery lost label identity", err)
			}
			for i := range view.Bindings {
				if len(view.Bindings[i].Label) > 0 {
					view.Bindings[i].Label[0] ^= 1
					break
				}
			}
			if err := e.MatchView(state, view); !errors.Is(err, engine.ErrCoordinateCollision) {
				t.Fatalf("view could substitute a label while retaining its coordinate: %v", err)
			}
			if err := e.ValidateState(t.Context(), root, state, nodes); err != nil {
				t.Fatal("snapshot exposed mutable authentication cells", err)
			}
			if _, err := e.Build(t.Context(), engine.State{Descriptor: d, Entries: []engine.Entry{{Target: child}}}, nodes); err == nil {
				t.Fatal("missing label treated as authenticated empty label")
			}
		})
	}
}

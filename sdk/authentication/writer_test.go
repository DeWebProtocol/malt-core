package authentication_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/coordinate"
	"github.com/dewebprotocol/malt-core/derivation"
	"github.com/dewebprotocol/malt-core/engine"
	"github.com/dewebprotocol/malt-core/maltcid"
	"github.com/dewebprotocol/malt-core/sdk/authentication"
	cid "github.com/ipfs/go-cid"
)

func TestWriterStateOwnsLabelsAndPreservesMetadata(t *testing.T) {
	state := engine.State{
		Descriptor: maltcid.RootDescriptor{Layout: maltcid.List, DerivationProfile: uint8(derivation.Direct), Profile: maltcid.IPA256},
		Entries:    []engine.Entry{{Label: coordinate.EncodeIndex(0), Target: cid.MustParse("bafkqaaa")}},
		PayloadCID: cid.MustParse("bafkqaaa"),
	}
	w, err := authentication.BuildWriter(t.Context(), pathEngine(t), state)
	if err != nil {
		t.Fatal(err)
	}
	got, err := w.State(t.Context())
	if err != nil || !reflect.DeepEqual(got, state) {
		t.Fatalf("retained state = %+v, error = %v", got, err)
	}
	got.Entries[0].Label[0] = 0xff
	got.Entries[0].Target = cid.Undef
	got.PayloadCID = cid.Undef
	again, err := w.State(t.Context())
	if err != nil || !reflect.DeepEqual(again, state) {
		t.Fatalf("caller changed retained state: %+v, %v", again, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := w.State(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled state read: %v", err)
	}
	for _, uninitialized := range []*authentication.Writer{nil, {}} {
		if _, err := uninitialized.State(t.Context()); err == nil {
			t.Fatal("uninitialized writer returned state")
		}
	}
}

func TestSparseListWriterDeltaAndRecovery(t *testing.T) {
	ctx, e := t.Context(), pathEngine(t)
	value := cid.MustParse("bafkqaaa")
	state := engine.State{Descriptor: maltcid.RootDescriptor{Layout: maltcid.List, DerivationProfile: uint8(derivation.Direct), Profile: maltcid.IPA256}, PayloadCID: value}
	entry := func(i uint64) engine.Entry { return engine.Entry{Label: coordinate.EncodeIndex(i), Target: value} }
	state.Entries = []engine.Entry{entry(0), entry(2)}
	base, err := authentication.BuildWriter(ctx, e, state)
	if err != nil {
		t.Fatal(err)
	}
	const high = uint64(1) << 40
	state.Entries = []engine.Entry{entry(2), entry(high)}
	updated, err := base.Update(ctx, state)
	if err != nil {
		t.Fatal(err)
	}
	add := engine.Change{Label: coordinate.EncodeIndex(high), After: value}
	remove := engine.Change{Label: coordinate.EncodeIndex(0), Before: value}
	branch, err := base.Apply(ctx, authentication.Delta{Changes: []engine.Change{add, remove}})
	if err != nil || !branch.Root().Equals(updated.Root()) {
		t.Fatal("delta and full update disagree", err)
	}
	fresh, err := authentication.BuildWriter(ctx, e, state)
	if err != nil || !fresh.Root().Equals(updated.Root()) {
		t.Fatal("incremental root differs from fresh root", err)
	}
	candidate, err := updated.Export(ctx)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := authentication.NewWriter(ctx, e, candidate)
	if err != nil || recovered.Len() != 2 {
		t.Fatal("sparse candidate import", err)
	}
	cut := high - 1
	shrunk, err := recovered.Apply(ctx, authentication.Delta{Count: &cut})
	if err != nil {
		t.Fatal(err)
	}
	source, err := shrunk.Nodes()
	if err != nil {
		t.Fatal(err)
	}
	meta, _, err := e.ReadMetadata(ctx, shrunk.Root(), source)
	if err != nil || meta.Count != 3 || !meta.PayloadCID.Equals(value) {
		t.Fatal("truncated extent or metadata", err)
	}
	if _, err := shrunk.Apply(ctx, authentication.Delta{Count: &cut}); err == nil {
		t.Fatal("extended a List without a terminal binding")
	}
	original, err := base.State(ctx)
	if err != nil || len(original.Entries) != 2 || string(original.Entries[0].Label) != string(coordinate.EncodeIndex(0)) {
		t.Fatal("base changed", err)
	}
}

func TestWriterUpdatesEqualFreshBuild(t *testing.T) {
	e := pathEngine(t)
	target := cid.MustParse("bafkqaaa")
	other := cid.MustParse("bafkreigh2akiscaildcw4535x7k5vfhq56bqddhziq3p4mwfmlz4vfu2ta")
	for _, withPayload := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "with payload"}[withPayload], func(t *testing.T) {
			state := engine.State{Descriptor: maltcid.RootDescriptor{DerivationProfile: uint8(derivation.Direct), Layout: maltcid.List, Profile: maltcid.IPA256}}
			if withPayload {
				state.PayloadCID = target
			}
			base, err := authentication.Prepare(t.Context(), e, state)
			if err != nil {
				t.Fatal(err)
			}
			w, err := authentication.NewWriter(t.Context(), e, base)
			if err != nil {
				t.Fatal(err)
			}
			// Cross the IPA leaf-capacity boundary, update the opaque payload,
			// shrink across the boundary, then empty and regrow the sequence.
			for _, count := range []int{3, 256, 256, 510, 511, 255, 2, 0, 4} {
				state.Entries = make([]engine.Entry, count)
				for i := range state.Entries {
					state.Entries[i] = engine.Entry{Label: coordinate.EncodeIndex(uint64(i)), Target: target}
				}
				if count > 0 {
					state.Entries[count-1].Target = other
				}
				if withPayload {
					state.PayloadCID = other
				}
				next, err := w.Update(t.Context(), state)
				if err != nil {
					t.Fatalf("count %d: %v", count, err)
				}
				fresh, err := authentication.Prepare(t.Context(), e, state)
				if err != nil {
					t.Fatal(err)
				}
				got := next.Candidate()
				previous := w.Root().String()
				if next.Root().Equals(w.Root()) {
					previous = w.Candidate().Previous
				}
				if got.Root != fresh.Root || got.Previous != previous {
					t.Fatalf("count %d root mismatch", count)
				}
				if err := authentication.ValidateCandidate(t.Context(), e, got); err != nil {
					t.Fatal(err)
				}
				w = next
			}
		})
	}
	state := engine.State{Descriptor: maltcid.RootDescriptor{Layout: maltcid.Map, DerivationProfile: uint8(derivation.SHA256), Profile: maltcid.IPA256}, Entries: []engine.Entry{{Label: []byte("a"), Target: target}}}
	base, err := authentication.Prepare(t.Context(), e, state)
	if err != nil {
		t.Fatal(err)
	}
	w, err := authentication.NewWriter(t.Context(), e, base)
	if err != nil {
		t.Fatal(err)
	}
	state.Entries = []engine.Entry{{Label: []byte("b"), Target: other}, {Label: []byte("@payload"), Target: target}}
	next, err := w.Update(t.Context(), state)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := authentication.Prepare(t.Context(), e, state)
	if err != nil {
		t.Fatal(err)
	}
	if next.Candidate().Root != fresh.Root || w.Candidate().Root != base.Root {
		t.Fatal("Map update or immutable base mismatch")
	}
	detached := next.Candidate()
	detached.State.Entries[0].Label[0] = 'x'
	detached.Nodes[0].Cells[0] = []byte("bad")
	if err := authentication.ValidateCandidate(t.Context(), e, next.Candidate()); err != nil {
		t.Fatal("candidate aliases writer", err)
	}
	state.Entries = append(state.Entries, state.Entries[0])
	if _, err := w.Update(t.Context(), state); err == nil {
		t.Fatal("duplicate coordinate accepted")
	}
	if w.Candidate().Root != base.Root {
		t.Fatal("failed update changed base")
	}
}

func TestWriterFillsPartialInternalTailBeforeAppend(t *testing.T) {
	e := pathEngine(t)
	state := engine.State{Descriptor: maltcid.RootDescriptor{DerivationProfile: uint8(derivation.Direct), Layout: maltcid.List, Profile: maltcid.IPA256}, PayloadCID: cid.MustParse("bafkqaaa")}
	for i := uint64(0); i < 510; i++ {
		state.Entries = append(state.Entries, engine.Entry{Label: coordinate.EncodeIndex(i), Target: cid.MustParse("bafkqaaa")})
	}
	base, err := authentication.Prepare(t.Context(), e, state)
	if err != nil {
		t.Fatal(err)
	}
	w, err := authentication.NewWriter(t.Context(), e, base)
	if err != nil {
		t.Fatal(err)
	}
	for _, count := range []uint64{510, 511} {
		if count > uint64(len(state.Entries)) {
			state.Entries = append(state.Entries, engine.Entry{Label: coordinate.EncodeIndex(count - 1), Target: cid.MustParse("bafkqaaa")})
		}
		w, err = w.Update(t.Context(), state)
		if err != nil {
			t.Fatal(err)
		}
		fresh, err := authentication.Prepare(t.Context(), e, state)
		if err != nil {
			t.Fatal(err)
		}
		if w.Candidate().Root != fresh.Root {
			t.Fatal("internal tail differs from fresh build")
		}
	}
}

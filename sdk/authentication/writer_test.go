package authentication_test

import (
	"testing"

	"github.com/dewebprotocol/malt-core/auth/coordinate"
	"github.com/dewebprotocol/malt-core/derivation"
	"github.com/dewebprotocol/malt-core/engine"
	"github.com/dewebprotocol/malt-core/maltcid"
	"github.com/dewebprotocol/malt-core/sdk/authentication"
	cid "github.com/ipfs/go-cid"
)

func TestWriterUpdatesEqualFreshBuild(t *testing.T) {
	e := pathEngine(t)
	target := cid.MustParse("bafkqaaa")
	other := cid.MustParse("bafkreigh2akiscaildcw4535x7k5vfhq56bqddhziq3p4mwfmlz4vfu2ta")
	for _, measured := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "measured"}[measured], func(t *testing.T) {
			state := engine.State{Descriptor: maltcid.RootDescriptor{DerivationProfile: uint8(derivation.Direct), Layout: maltcid.Positional, Profile: maltcid.IPA256}}
			if measured {
				state.ChunkSize = 8
			}
			base, err := authentication.Prepare(t.Context(), e, state)
			if err != nil {
				t.Fatal(err)
			}
			w, err := authentication.NewWriter(t.Context(), e, base)
			if err != nil {
				t.Fatal(err)
			}
			// Cross the IPA leaf-capacity boundary, change a partial final chunk,
			// shrink across the boundary, then empty and regrow the sequence.
			for _, count := range []int{3, 256, 256, 510, 511, 255, 2, 0, 4} {
				state.Entries = make([]engine.Entry, count)
				for i := range state.Entries {
					state.Entries[i] = engine.Entry{Label: coordinate.EncodeIndex(uint64(i)), Target: target}
				}
				if count > 0 {
					state.Entries[count-1].Target = other
				}
				if measured {
					state.TotalSize = uint64(count) * 8
					if count > 0 {
						state.TotalSize -= 3
					}
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
	state := engine.State{Descriptor: maltcid.RootDescriptor{Layout: maltcid.Prefix, DerivationProfile: uint8(derivation.SHA256), Profile: maltcid.IPA256}, Entries: []engine.Entry{{Label: []byte("a"), Target: target}}}
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
		t.Fatal("Prefix update or immutable base mismatch")
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
	state := engine.State{Descriptor: maltcid.RootDescriptor{DerivationProfile: uint8(derivation.Direct), Layout: maltcid.Positional, Profile: maltcid.IPA256}, ChunkSize: 8, TotalSize: 510*8 - 3}
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
		state.TotalSize = count * 8
		w, err = w.Update(t.Context(), state)
		if err != nil {
			t.Fatal(err)
		}
		fresh, err := authentication.Prepare(t.Context(), e, state)
		if err != nil {
			t.Fatal(err)
		}
		if w.Candidate().Root != fresh.Root {
			t.Fatal("internal tail metadata differs from fresh build")
		}
	}
}

func TestWriterMeasuredPartialTailAtUint64Boundary(t *testing.T) {
	e := pathEngine(t)
	state := engine.State{Descriptor: maltcid.RootDescriptor{DerivationProfile: uint8(derivation.Direct), Layout: maltcid.Positional, Profile: maltcid.IPA256}, ChunkSize: 1 << 63, TotalSize: 1 << 63, Entries: []engine.Entry{{Label: coordinate.EncodeIndex(0), Target: cid.MustParse("bafkqaaa")}}}
	base, err := authentication.Prepare(t.Context(), e, state)
	if err != nil {
		t.Fatal(err)
	}
	state.Entries = append(state.Entries, engine.Entry{Label: coordinate.EncodeIndex(1), Target: cid.MustParse("bafkqaaa")})
	state.TotalSize++
	next, err := authentication.PrepareUpdate(t.Context(), e, base, state)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := authentication.Prepare(t.Context(), e, state)
	if err != nil {
		t.Fatal(err)
	}
	if next.Root != fresh.Root {
		t.Fatal("valid partial tail overflowed")
	}
}

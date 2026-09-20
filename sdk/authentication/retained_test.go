package authentication_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
	"github.com/dewebprotocol/malt-core/auth/engine"
	"github.com/dewebprotocol/malt-core/auth/input"
	"github.com/dewebprotocol/malt-core/sdk/authentication"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

type countedVerifier struct {
	commitment.IndexCommitment
	calls int
}

func (c *countedVerifier) ProfileID() maltcid.ProfileID { return maltcid.IPA256 }
func (c *countedVerifier) VerifyIndex(r commitment.Value, i uint64, v commitment.Cell, p []byte) (bool, error) {
	c.calls++
	return c.IndexCommitment.VerifyIndex(r, i, v, p)
}
func (c *countedVerifier) PrepareOpeningAtRoot(r commitment.Value, v []commitment.Cell) (commitment.IndexOpening, error) {
	return c.IndexCommitment.(commitment.IndexRootOpener).PrepareOpeningAtRoot(r, v)
}

func TestRetainedWriterDoesNotRevalidateOwnedNodes(t *testing.T) {
	scheme, err := ipa.NewCommitterScheme(ipa.ProfileDirect)
	if err != nil {
		t.Fatal(err)
	}
	counted := &countedVerifier{IndexCommitment: scheme}
	profiles := engine.NewRegistry()
	if err := profiles.Register(counted); err != nil {
		t.Fatal(err)
	}
	e := engine.New(input.DefaultRegistry(), profiles)
	target := cid.MustParse("bafkqaaa")
	other := cid.MustParse("bafkreigh2akiscaildcw4535x7k5vfhq56bqddhziq3p4mwfmlz4vfu2ta")
	for _, n := range []int{1, 256, 511} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			state := engine.State{Descriptor: maltcid.RootDescriptor{Layout: maltcid.Positional, Profile: maltcid.IPA256}}
			for i := 0; i < n; i++ {
				state.Entries = append(state.Entries, engine.Entry{Input: input.IndexValue(uint64(i)), Target: target})
			}
			candidate, err := authentication.Prepare(t.Context(), e, state)
			if err != nil {
				t.Fatal(err)
			}
			counted.calls = 0
			w, err := authentication.NewWriter(t.Context(), e, candidate)
			if err != nil {
				t.Fatal(err)
			}
			if counted.calls == 0 {
				t.Fatal("untrusted import was not verified")
			}
			counted.calls = 0
			unchanged, err := w.Update(t.Context(), state)
			if err != nil {
				t.Fatal(err)
			}
			if !unchanged.Root().Equals(w.Root()) || counted.calls != 0 {
				t.Fatalf("no-op revalidated %d nodes", counted.calls)
			}
			next, err := w.Apply(t.Context(), authentication.Delta{Changes: []engine.Change{{Input: input.IndexValue(0), Before: target, After: other}}})
			if err != nil {
				t.Fatal(err)
			}
			if counted.calls != 0 {
				t.Fatalf("owned state was revalidated %d times", counted.calls)
			}
			exported, err := next.Export(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if counted.calls != 0 {
				t.Fatal("owned export repeated cryptographic verification")
			}
			state.Entries[0].Target = other
			fresh, err := authentication.Prepare(t.Context(), e, state)
			if err != nil {
				t.Fatal(err)
			}
			if exported.Root != fresh.Root || w.Candidate().Root != candidate.Root {
				t.Fatal("incremental root or base isolation mismatch")
			}
			if err := authentication.ValidateCandidate(t.Context(), e, exported); err != nil {
				t.Fatal(err)
			}
			// Imported bytes do not acquire the private owned-node capability.
			exported.Nodes[0].Cells[1] = []byte("corrupt")
			if _, err := authentication.NewWriter(t.Context(), e, exported); err == nil {
				t.Fatal("corrupt import bypassed verification")
			}
		})
	}
}

func TestDeltaRejectsWrongBeforeAndPreservesBranches(t *testing.T) {
	e := pathEngine(t)
	value := cid.MustParse("bafkqaaa")
	other := cid.MustParse("bafkreigh2akiscaildcw4535x7k5vfhq56bqddhziq3p4mwfmlz4vfu2ta")
	state := engine.State{Descriptor: maltcid.RootDescriptor{Layout: maltcid.Prefix, InputRule: 1, Profile: maltcid.IPA256}, Entries: []engine.Entry{{Input: input.LabelValue([]byte("base")), Target: value}}}
	w, err := authentication.BuildWriter(t.Context(), e, state)
	if err != nil {
		t.Fatal(err)
	}
	bad := authentication.Delta{Changes: []engine.Change{{Input: state.Entries[0].Input, Before: other, After: value}}}
	if _, err := w.Apply(t.Context(), bad); err == nil {
		t.Fatal("wrong before accepted")
	}
	insertion := engine.Change{Input: input.LabelValue([]byte("branch")), After: other}
	a, err := w.Apply(t.Context(), authentication.Delta{Changes: []engine.Change{insertion}})
	if err != nil {
		t.Fatal(err)
	}
	insertion.Input.Data[0] = 'x'
	b, err := w.Apply(t.Context(), authentication.Delta{Changes: []engine.Change{{Input: state.Entries[0].Input, Before: value}}})
	if err != nil {
		t.Fatal(err)
	}
	if a.Root().Equals(b.Root()) || w.Root().Equals(b.Root()) {
		t.Fatal("branches share mutable state")
	}
	if err := authentication.ValidateCandidate(t.Context(), e, a.Candidate()); err != nil {
		t.Fatal("caller mutated owned input", err)
	}
	if err := authentication.ValidateCandidate(t.Context(), e, b.Candidate()); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := a.Apply(cancelled, authentication.Delta{}); err == nil {
		t.Fatal("cancelled update succeeded")
	}
}

func TestRetainedSessionBoundsAndHandleLifetime(t *testing.T) {
	e := pathEngine(t)
	state := engine.State{Descriptor: maltcid.RootDescriptor{Layout: maltcid.Prefix, InputRule: 1, Profile: maltcid.IPA256}}
	s, err := authentication.NewSession(e, authentication.SessionLimits{MaxCandidates: 2})
	if err != nil {
		t.Fatal(err)
	}
	a, err := s.Build(t.Context(), state)
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.Apply(t.Context(), a.ID, authentication.Delta{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Apply(t.Context(), a.ID, authentication.Delta{}); err == nil {
		t.Fatal("candidate limit ignored")
	}
	if err := s.Discard(a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Export(t.Context(), a.ID); err == nil {
		t.Fatal("discarded handle remains live")
	}
	if _, err := s.Export(t.Context(), b.ID); err != nil {
		t.Fatal("discard removed another branch", err)
	}
	s.Clear()
	c, err := s.Build(t.Context(), state)
	if err != nil {
		t.Fatal(err)
	}
	if c.ID == a.ID || c.ID == b.ID {
		t.Fatal("reset reused a stale handle")
	}
	tiny, err := authentication.NewSession(e, authentication.SessionLimits{MaxStateBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tiny.Build(t.Context(), state); err == nil {
		t.Fatal("state byte budget ignored")
	}
}

func TestRetainedPrefixMixedDeltasMatchRebuild(t *testing.T) {
	e := pathEngine(t)
	state := engine.State{Descriptor: maltcid.RootDescriptor{Layout: maltcid.Prefix, InputRule: 1, Profile: maltcid.IPA256}}
	w, err := authentication.BuildWriter(t.Context(), e, state)
	if err != nil {
		t.Fatal(err)
	}
	values := []cid.Cid{cid.MustParse("bafkqaaa"), cid.MustParse("bafkreigh2akiscaildcw4535x7k5vfhq56bqddhziq3p4mwfmlz4vfu2ta")}
	want := make(map[string]cid.Cid)
	// Distinct hashed routes exercise insertions, replacements and collapsed
	// deletion paths in both immutable indexes. Compare public Roots and exports
	// with fresh construction instead of asserting private trie structure.
	for round := 0; round < 5; round++ {
		delta := authentication.Delta{}
		for i := 0; i < 48; i++ {
			label := fmt.Sprintf("relation-%d", i)
			before := want[label]
			after := values[(i+round)%len(values)]
			if (i+round)%3 == 0 {
				after = cid.Undef
			}
			if before.Equals(after) {
				continue
			}
			delta.Changes = append(delta.Changes, engine.Change{Input: input.LabelValue([]byte(label)), Before: before, After: after})
			if after.Defined() {
				want[label] = after
			} else {
				delete(want, label)
			}
		}
		base := w
		w, err = w.Apply(t.Context(), delta)
		if err != nil {
			t.Fatal(round, err)
		}
		state.Entries = nil
		for label, target := range want {
			state.Entries = append(state.Entries, engine.Entry{Input: input.LabelValue([]byte(label)), Target: target})
		}
		fresh, err := authentication.BuildWriter(t.Context(), e, state)
		if err != nil || !fresh.Root().Equals(w.Root()) {
			t.Fatal("delta differs from reconstruction", round, err)
		}
		for _, branch := range []*authentication.Writer{base, w} {
			if err := authentication.ValidateCandidate(t.Context(), e, branch.Candidate()); err != nil {
				t.Fatal("invalid retained branch", round, err)
			}
		}
	}
}

type rewritingExportSource struct{ nodes *memory.Nodes }

func (s rewritingExportSource) GetNode(ctx context.Context, ref maltcid.NodeRef) ([]commitment.Cell, error) {
	cells, err := s.nodes.GetNode(ctx, ref)
	clear(ref.Commitment)
	return cells, err
}

func TestExportIsolatesCollectorReferenceFromSource(t *testing.T) {
	e := pathEngine(t)
	nodes := memory.NewNodes()
	state := engine.State{Descriptor: maltcid.RootDescriptor{Layout: maltcid.Positional, Profile: maltcid.IPA256}, Entries: []engine.Entry{{Input: input.IndexValue(0), Target: cid.MustParse("bafkqaaa")}}}
	root, err := e.Build(t.Context(), state, nodes)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := authentication.Export(t.Context(), e, root, state, rewritingExportSource{nodes})
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Root != root.String() {
		t.Fatal("source altered exported Root")
	}
	if err := authentication.ValidateCandidate(t.Context(), e, candidate); err != nil {
		t.Fatal("source corrupted the exported node references", err)
	}
}

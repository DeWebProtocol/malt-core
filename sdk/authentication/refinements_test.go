package authentication_test

import (
	"fmt"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
	"github.com/dewebprotocol/malt-core/auth/commitment/kzg"
	"github.com/dewebprotocol/malt-core/auth/coordinate"
	"github.com/dewebprotocol/malt-core/derivation"
	"github.com/dewebprotocol/malt-core/engine"
	"github.com/dewebprotocol/malt-core/maltcid"
	"github.com/dewebprotocol/malt-core/sdk/authentication"
	cid "github.com/ipfs/go-cid"
)

type candidateWork struct {
	commitment.Backend
	profile                     maltcid.ProfileID
	commits, prepares, verifies int
}

func (c *candidateWork) ProfileID() maltcid.ProfileID { return c.profile }
func (c *candidateWork) Commit(v []commitment.Cell) (commitment.Value, error) {
	c.commits++
	return c.Backend.Commit(v)
}
func (c *candidateWork) PrepareOpening(r commitment.Value, v []commitment.Cell) (commitment.Opening, error) {
	c.prepares++
	return c.Backend.(commitment.PreparedProver).PrepareOpening(r, v)
}
func (c *candidateWork) VerifyIndex(r commitment.Value, i uint64, v commitment.Cell, p []byte) (bool, error) {
	c.verifies++
	return c.Backend.VerifyIndex(r, i, v, p)
}
func candidateEngine(t *testing.T, profile maltcid.ProfileID) (*engine.Engine, *candidateWork) {
	t.Helper()
	var backend commitment.Backend
	var err error
	if profile == maltcid.IPA256 {
		backend, err = ipa.NewCommitterScheme(ipa.ProfileDirect)
	} else {
		backend, err = kzg.NewScheme()
	}
	if err != nil {
		t.Fatal(err)
	}
	c := &candidateWork{Backend: backend, profile: profile}
	profiles := engine.NewRegistry()
	if err := profiles.Register(c); err != nil {
		t.Fatal(err)
	}
	return engine.New(profiles), c
}

func TestExportOwnsRetainedInputs(t *testing.T) {
	e := pathEngine(t)
	target := cid.MustParse("bafkqaaa")
	state := engine.State{Descriptor: maltcid.RootDescriptor{Layout: maltcid.Prefix, DerivationProfile: uint8(derivation.SHA256), Profile: maltcid.IPA256}, Entries: []engine.Entry{{Label: []byte("entry"), Target: target}}}
	nodes := memory.NewNodes()
	root, err := e.Build(t.Context(), state, nodes)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := authentication.Export(t.Context(), e, root, state, nodes)
	if err != nil {
		t.Fatal(err)
	}
	state.Entries[0].Label[0] = 'X'
	state.Entries[0].Target = cid.Undef
	if err := authentication.ValidateCandidate(t.Context(), e, candidate); err != nil {
		t.Fatal("input mutation changed export", err)
	}
	candidate.State.Entries[0].Label[1] = 'Y'
	candidate.State.Entries[0].Target = target
	if string(state.Entries[0].Label) != "Xntry" || state.Entries[0].Target.Defined() {
		t.Fatal("export mutation changed caller state")
	}
}

func TestCandidateVerifiesSharedNodesOnce(t *testing.T) {
	e, work := candidateEngine(t, maltcid.IPA256)
	state := engine.State{Descriptor: maltcid.RootDescriptor{DerivationProfile: uint8(derivation.Direct), Layout: maltcid.Positional, Profile: maltcid.IPA256}}
	for i := uint64(0); i < 1020; i++ {
		state.Entries = append(state.Entries, engine.Entry{Label: coordinate.EncodeIndex(i), Target: cid.MustParse("bafkqaaa")})
	}
	candidate, err := authentication.Prepare(t.Context(), e, state)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidate.Nodes) != 2 {
		t.Fatalf("expected two physical nodes, got %d", len(candidate.Nodes))
	}
	for range 2 {
		work.prepares, work.verifies = 0, 0
		if err := authentication.ValidateCandidate(t.Context(), e, candidate); err != nil {
			t.Fatal(err)
		}
		if work.prepares != 2 || work.verifies != 2 {
			t.Fatalf("prepare/verify = %d/%d, want 2/2", work.prepares, work.verifies)
		}
	}
	candidate.Nodes[0].Cells[1] = []byte("corrupt")
	if err := authentication.ValidateCandidate(t.Context(), e, candidate); err == nil {
		t.Fatal("verification reused across calls")
	}
}

func TestBulkAppendCommitsEachChangedNodeOnce(t *testing.T) {
	for _, tc := range []struct {
		profile                maltcid.ProfileID
		before, after, commits int
	}{
		{maltcid.IPA256, 0, 64, 1}, {maltcid.KZG4096, 0, 64, 1},
		{maltcid.IPA256, 1, 254, 1}, {maltcid.IPA256, 254, 600, 4},
		{maltcid.IPA256, 510, 520, 2}, {maltcid.KZG4096, 4094, 4097, 3},
	} {
		t.Run(fmt.Sprintf("%d/%d-%d", tc.profile, tc.before, tc.after), func(t *testing.T) {
			e, work := candidateEngine(t, tc.profile)
			state := engine.State{Descriptor: maltcid.RootDescriptor{DerivationProfile: uint8(derivation.Direct), Layout: maltcid.Positional, Profile: tc.profile}}
			target := cid.MustParse("bafkqaaa")
			for i := 0; i < tc.before; i++ {
				state.Entries = append(state.Entries, engine.Entry{Label: coordinate.EncodeIndex(uint64(i)), Target: target})
			}
			base, err := authentication.BuildWriter(t.Context(), e, state)
			if err != nil {
				t.Fatal(err)
			}
			count := uint64(tc.after)
			delta := authentication.Delta{Count: &count}
			for i := tc.before; i < tc.after; i++ {
				entry := engine.Entry{Label: coordinate.EncodeIndex(uint64(i)), Target: target}
				state.Entries = append(state.Entries, entry)
				delta.Changes = append(delta.Changes, engine.Change{Label: entry.Label, After: target})
			}
			work.commits = 0
			next, err := base.Apply(t.Context(), delta)
			if err != nil {
				t.Fatal(err)
			}
			if work.commits != tc.commits {
				t.Fatalf("commits = %d, want %d", work.commits, tc.commits)
			}
			fresh, err := authentication.BuildWriter(t.Context(), e, state)
			if err != nil {
				t.Fatal(err)
			}
			if !next.Root().Equals(fresh.Root()) {
				t.Fatal("bulk append differs from rebuild")
			}
			if err := authentication.ValidateCandidate(t.Context(), e, next.Candidate()); err != nil {
				t.Fatal(err)
			}
			if len(base.Candidate().State.Entries) != tc.before {
				t.Fatal("base writer mutated")
			}
		})
	}
}

package engine_test

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer"
	"github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
	"github.com/dewebprotocol/malt-core/auth/commitment/kzg"
	"github.com/dewebprotocol/malt-core/auth/coordinate"
	"github.com/dewebprotocol/malt-core/derivation"
	"github.com/dewebprotocol/malt-core/engine"
	"github.com/dewebprotocol/malt-core/maltcid"
)

type openingCounter struct {
	commitment.Backend
	profile                                  maltcid.ProfileID
	mu                                       sync.Mutex
	prepared, opened, verified, provedAtRoot int
}

func (s *openingCounter) ProfileID() maltcid.ProfileID { return s.profile }
func (s *openingCounter) PrepareOpening(root commitment.Value, cells []commitment.Cell) (commitment.Opening, error) {
	s.mu.Lock()
	s.prepared++
	s.mu.Unlock()
	opening, err := s.Backend.(commitment.PreparedProver).PrepareOpening(root, cells)
	if err != nil {
		return nil, err
	}
	return &countedOpening{Opening: opening, owner: s}, nil
}
func (s *openingCounter) Prove(root commitment.Value, cells []commitment.Cell, index uint64) (commitment.Cell, []byte, error) {
	s.mu.Lock()
	s.provedAtRoot++
	s.mu.Unlock()
	return s.Backend.(commitment.Prover).Prove(root, cells, index)
}
func (s *openingCounter) BatchProve(root commitment.Value, cells []commitment.Cell, indices []uint64) ([]commitment.Cell, []byte, error) {
	s.mu.Lock()
	s.provedAtRoot++
	s.mu.Unlock()
	return s.Backend.(commitment.Prover).BatchProve(root, cells, indices)
}
func (s *openingCounter) VerifyIndex(root commitment.Value, index uint64, value commitment.Cell, proof []byte) (bool, error) {
	s.mu.Lock()
	s.verified++
	s.mu.Unlock()
	return s.Backend.VerifyIndex(root, index, value, proof)
}

type countedOpening struct {
	commitment.Opening
	owner *openingCounter
}

func (p *countedOpening) Open(index uint64) (commitment.Cell, []byte, error) {
	p.owner.mu.Lock()
	p.owner.opened++
	p.owner.mu.Unlock()
	return p.Opening.Open(index)
}

type corruptVector struct{ materializer.NodeLookup }

func (s corruptVector) GetNode(ctx context.Context, ref maltcid.NodeRef) ([]commitment.Cell, error) {
	cells, err := s.NodeLookup.GetNode(ctx, ref)
	if err != nil {
		return nil, err
	}
	cells = commitment.CloneCells(cells)
	cells[0] = commitment.NewCell([]byte("corrupt materialization"))
	return cells, nil
}

// Change a slot outside the successful query without breaking its routing or
// metadata. Only cryptographic verification can detect this inconsistent vector.
type corruptUnselectedCell struct{ materializer.NodeLookup }

func (s corruptUnselectedCell) GetNode(ctx context.Context, ref maltcid.NodeRef) ([]commitment.Cell, error) {
	cells, err := s.NodeLookup.GetNode(ctx, ref)
	if err != nil {
		return nil, err
	}
	cells = commitment.CloneCells(cells)
	for i := len(cells) - 1; i >= 0; i-- {
		if len(cells[i]) == 0 {
			cells[i] = commitment.NewCell([]byte("corrupt unselected cell"))
			return cells, nil
		}
	}
	return nil, fmt.Errorf("fixture has no unselected empty cell")
}

func TestEngineGeneratesEvidenceForIndependentVerification(t *testing.T) {
	for _, profile := range []maltcid.ProfileID{maltcid.IPA256, maltcid.KZG4096} {
		for _, layout := range []maltcid.Layout{maltcid.Map, maltcid.List} {
			t.Run(fmt.Sprintf("profile-%d/layout-%d", profile, layout), func(t *testing.T) {
				var scheme commitment.Backend
				var err error
				if profile == maltcid.IPA256 {
					scheme, err = ipa.NewCommitterScheme(ipa.ProfileDirect)
				} else {
					scheme, err = kzg.NewScheme()
				}
				if err != nil {
					t.Fatal(err)
				}
				counter := &openingCounter{Backend: scheme, profile: profile}
				registry := engine.NewRegistry()
				if err := registry.Register(counter); err != nil {
					t.Fatal(err)
				}
				e := engine.New(registry)
				nodes := memory.NewNodes()
				descriptor := maltcid.RootDescriptor{DerivationProfile: uint8(derivation.Direct), Layout: layout, Profile: profile}
				query := coordinate.EncodeIndex(0)
				wantOpenings := 2
				if layout == maltcid.Map {
					descriptor.DerivationProfile = uint8(derivation.SHA256)
					query = []byte("entry")
					wantOpenings = 1
				}
				root, err := e.Build(t.Context(), engine.State{Descriptor: descriptor, Entries: []engine.Entry{{Label: query, Target: target("value")}}}, nodes)
				if err != nil {
					t.Fatal(err)
				}
				counter.prepared, counter.opened, counter.verified = 0, 0, 0
				result, err := e.Prove(t.Context(), root, query, nodes)
				if err != nil {
					t.Fatal(err)
				}
				if counter.prepared != 1 || counter.opened != wantOpenings || counter.verified != 0 || counter.provedAtRoot != 0 {
					t.Fatalf("preparations/openings/verifications/root proofs = %d/%d/%d/%d, want 1/%d/0/0", counter.prepared, counter.opened, counter.verified, counter.provedAtRoot, wantOpenings)
				}
				if valid, err := e.Verify(root, query, result); err != nil || !valid {
					t.Fatalf("portable verification: %v", err)
				}
				if counter.verified != wantOpenings {
					t.Fatal("receiver did not verify each opening")
				}
				counter.verified = 0
				corrupt := corruptUnselectedCell{nodes}
				bad, err := e.Prove(t.Context(), root, query, corrupt)
				if err != nil || counter.verified != 0 {
					t.Fatalf("generation performed verification: %v, calls=%d", err, counter.verified)
				}
				if valid, _ := e.Verify(root, query, bad); valid {
					t.Fatal("receiver accepted inconsistent materialization")
				}
				counter.verified = 0
				if _, err := e.Snapshot(t.Context(), root, corrupt); err == nil || counter.verified == 0 {
					t.Fatal("snapshot did not cryptographically reject inconsistent materialization")
				}
				if layout == maltcid.List {
					counter.verified = 0
					if _, _, err := e.ReadMetadata(t.Context(), root, corrupt); err == nil || counter.verified == 0 {
						t.Fatal("metadata consumer did not verify untrusted materialization")
					}
				}
			})
		}
	}
}

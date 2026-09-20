package engine_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer"
	"github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
	"github.com/dewebprotocol/malt-core/auth/commitment/kzg"
	"github.com/dewebprotocol/malt-core/auth/engine"
	"github.com/dewebprotocol/malt-core/auth/input"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
)

type openingCounter struct {
	commitment.IndexCommitment
	profile                                  maltcid.ProfileID
	prepared, opened, verified, provedAtRoot int
}

func (s *openingCounter) ProfileID() maltcid.ProfileID { return s.profile }
func (s *openingCounter) PrepareOpeningAtRoot(root commitment.Value, cells []commitment.Cell) (commitment.IndexOpening, error) {
	s.prepared++
	opening, err := s.IndexCommitment.(commitment.IndexRootOpener).PrepareOpeningAtRoot(root, cells)
	if err != nil {
		return nil, err
	}
	return &countedOpening{IndexOpening: opening, owner: s}, nil
}
func (s *openingCounter) ProveAtRoot(root commitment.Value, cells []commitment.Cell, index uint64) (commitment.Cell, []byte, error) {
	s.provedAtRoot++
	return s.IndexCommitment.(commitment.IndexRootProver).ProveAtRoot(root, cells, index)
}
func (s *openingCounter) BatchProveAtRoot(root commitment.Value, cells []commitment.Cell, indices []uint64) ([]commitment.Cell, []byte, error) {
	s.provedAtRoot++
	return s.IndexCommitment.(commitment.IndexRootProver).BatchProveAtRoot(root, cells, indices)
}
func (s *openingCounter) VerifyIndex(root commitment.Value, index uint64, value commitment.Cell, proof []byte) (bool, error) {
	s.verified++
	return s.IndexCommitment.VerifyIndex(root, index, value, proof)
}

type countedOpening struct {
	commitment.IndexOpening
	owner *openingCounter
}

func (p *countedOpening) Open(index uint64) (commitment.Cell, []byte, error) {
	p.owner.opened++
	return p.IndexOpening.Open(index)
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

func TestEngineVerifiesEachGeneratedOpeningOnce(t *testing.T) {
	for _, profile := range []maltcid.ProfileID{maltcid.IPA256, maltcid.KZG4096} {
		for _, layout := range []maltcid.Layout{maltcid.Prefix, maltcid.Positional} {
			t.Run(fmt.Sprintf("profile-%d/layout-%d", profile, layout), func(t *testing.T) {
				var scheme commitment.IndexCommitment
				var err error
				if profile == maltcid.IPA256 {
					scheme, err = ipa.NewCommitterScheme(ipa.ProfileDirect)
				} else {
					scheme, err = kzg.NewScheme()
				}
				if err != nil {
					t.Fatal(err)
				}
				counter := &openingCounter{IndexCommitment: scheme, profile: profile}
				registry := engine.NewRegistry()
				if err := registry.Register(counter); err != nil {
					t.Fatal(err)
				}
				e := engine.New(input.DefaultRegistry(), registry)
				nodes := memory.NewNodes()
				descriptor := maltcid.RootDescriptor{Layout: layout, Profile: profile}
				query := input.IndexValue(0)
				wantOpenings := 2
				if layout == maltcid.Prefix {
					descriptor.InputRule = uint8(input.BytesSHA256)
					query = input.LabelValue([]byte("entry"))
					wantOpenings = 1
				}
				root, err := e.Build(t.Context(), engine.State{Descriptor: descriptor, Entries: []engine.Entry{{Input: query, Target: target("value")}}}, nodes)
				if err != nil {
					t.Fatal(err)
				}
				counter.prepared, counter.opened, counter.verified = 0, 0, 0
				result, err := e.Prove(t.Context(), root, query, nodes)
				if err != nil {
					t.Fatal(err)
				}
				if counter.prepared != wantOpenings || counter.opened != wantOpenings || counter.verified != wantOpenings || counter.provedAtRoot != 0 {
					t.Fatalf("preparations/openings/verifications/root proofs = %d/%d/%d/%d, want %d/%d/%d/0", counter.prepared, counter.opened, counter.verified, counter.provedAtRoot, wantOpenings, wantOpenings, wantOpenings)
				}
				if valid, err := e.Verify(root, query, result); err != nil || !valid {
					t.Fatalf("portable verification: %v", err)
				}
				if _, err := e.Prove(t.Context(), root, query, corruptVector{nodes}); err == nil {
					t.Fatal("untrusted vector opened against a different commitment")
				}
			})
		}
	}
}

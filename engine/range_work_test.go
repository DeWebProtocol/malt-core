package engine_test

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer"
	"github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
	"github.com/dewebprotocol/malt-core/auth/commitment/kzg"
	"github.com/dewebprotocol/malt-core/auth/coordinate"
	"github.com/dewebprotocol/malt-core/derivation"
	"github.com/dewebprotocol/malt-core/engine"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
)

// Reuse the returned backing vector on the next load, as a streaming storage
// adapter may do. The query must detach it and never request the same node twice.
type rangeNodes struct {
	materializer.NodeLookup
	reads  map[string]int
	buffer []commitment.Cell
}

func (s *rangeNodes) GetNode(ctx context.Context, ref maltcid.NodeRef) ([]commitment.Cell, error) {
	key, err := ref.Bytes()
	if err != nil {
		return nil, err
	}
	s.reads[string(key)]++
	if s.reads[string(key)] != 1 {
		return nil, fmt.Errorf("repeated node read")
	}
	cells, err := s.NodeLookup.GetNode(ctx, ref)
	if err != nil {
		return nil, err
	}
	s.buffer = append(s.buffer[:0], cells...)
	return s.buffer, nil
}

func TestRangeReusesVerifiedNodeWork(t *testing.T) {
	for _, tc := range []struct {
		name              string
		profile           maltcid.ProfileID
		count, start, end uint64
		nodes, openings   int
		prepared          bool
	}{
		{"ipa leaf", maltcid.IPA256, 8, 0, 8, 1, 9, true},
		{"kzg leaf", maltcid.KZG4096, 8, 0, 8, 1, 9, true},
		{"ipa crossing children", maltcid.IPA256, 258, 253, 257, 3, 9, true},
		{"prover without preparation", maltcid.IPA256, 8, 0, 8, 1, 9, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var scheme commitment.Backend
			var err error
			if tc.profile == maltcid.IPA256 {
				scheme, err = ipa.NewCommitterScheme(ipa.ProfileDirect)
			} else {
				scheme, err = kzg.NewScheme()
			}
			if err != nil {
				t.Fatal(err)
			}
			counter := &openingCounter{Backend: scheme, profile: tc.profile}
			profiles := engine.NewRegistry()
			if err := profiles.Register(counter); err != nil {
				t.Fatal(err)
			}
			e := engine.New(profiles)
			store := memory.NewNodes()
			state := engine.State{Descriptor: maltcid.RootDescriptor{DerivationProfile: uint8(derivation.Direct), Layout: maltcid.Positional, Profile: tc.profile}, ChunkSize: 1, TotalSize: tc.count}
			for i := uint64(0); i < tc.count; i++ {
				state.Entries = append(state.Entries, engine.Entry{Label: coordinate.EncodeIndex(i), Target: target(fmt.Sprint(i))})
			}
			root, err := e.Build(t.Context(), state, store)
			if err != nil {
				t.Fatal(err)
			}
			if !tc.prepared {
				profiles = engine.NewRegistry()
				if err := profiles.Register(proofProfile{Prover: counter, Verifier: counter, id: tc.profile}); err != nil {
					t.Fatal(err)
				}
				e = engine.New(profiles)
			}
			nodes := &rangeNodes{NodeLookup: store, reads: make(map[string]int)}
			result, err := e.ProveRange(t.Context(), root, tc.start, &tc.end, nodes)
			if err != nil {
				t.Fatal(err)
			}
			if len(nodes.reads) != tc.nodes {
				t.Fatalf("read %d distinct nodes, want %d", len(nodes.reads), tc.nodes)
			}
			if counter.verified != tc.openings {
				t.Fatalf("verified %d openings, want %d", counter.verified, tc.openings)
			}
			if tc.prepared {
				if counter.prepared != tc.nodes || counter.opened != tc.openings || counter.provedAtRoot != 0 {
					t.Fatalf("prepare/open/prove = %d/%d/%d", counter.prepared, counter.opened, counter.provedAtRoot)
				}
			} else if counter.prepared != 0 || counter.provedAtRoot != tc.openings {
				t.Fatal("unprepared prover work mismatch")
			}
			if valid, err := e.VerifyRange(root, tc.start, &tc.end, result); err != nil || !valid {
				t.Fatalf("verify = %v, %v", valid, err)
			}
			// Shared metadata openings must not alias returned evidence.
			metadata := bytes.Clone(result.MetadataEvidence.Proof.Nodes[0].Metadata)
			proof := bytes.Clone(result.MetadataEvidence.Proof.Nodes[0].MetadataProof)
			result.Segments[0].Proof.Nodes[0].Metadata[0] ^= 1
			result.Segments[0].Proof.Nodes[0].MetadataProof[0] ^= 1
			if !bytes.Equal(metadata, result.MetadataEvidence.Proof.Nodes[0].Metadata) ||
				!bytes.Equal(metadata, result.Segments[1].Proof.Nodes[0].Metadata) ||
				!bytes.Equal(proof, result.MetadataEvidence.Proof.Nodes[0].MetadataProof) ||
				!bytes.Equal(proof, result.Segments[1].Proof.Nodes[0].MetadataProof) {
				t.Fatal("returned evidence aliases another result")
			}
			// A new call must consult and check its own materializer, even at
			// a Root successfully queried by the same engine before.
			if _, err := e.ProveRange(t.Context(), root, tc.start, &tc.end, corruptVector{store}); err == nil {
				t.Fatal("reused evidence across calls")
			}
			canceled, cancel := context.WithCancel(t.Context())
			cancel()
			if _, err := e.ProveRange(canceled, root, tc.start, &tc.end, store); err == nil {
				t.Fatal("ignored cancellation")
			}
		})
	}
}

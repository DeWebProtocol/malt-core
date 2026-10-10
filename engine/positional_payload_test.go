package engine_test

import (
	"fmt"
	"github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/coordinate"
	"github.com/dewebprotocol/malt-core/derivation"
	"github.com/dewebprotocol/malt-core/engine"
	"github.com/dewebprotocol/malt-core/maltcid"
	cid "github.com/ipfs/go-cid"
	"testing"
)

func TestRootOnlyMetadataAcrossGrowthAndCollapse(t *testing.T) {
	for _, profile := range []maltcid.ProfileID{maltcid.IPA256, maltcid.KZG4096} {
		t.Run(fmt.Sprint(profile), func(t *testing.T) {
			e, base := setup(t, profile)
			nodes := &countedNodes{Nodes: base}
			p, _ := maltcid.Profile(profile)
			state := engine.State{Descriptor: maltcid.RootDescriptor{Layout: maltcid.Positional, DerivationProfile: uint8(derivation.Direct), Profile: profile}, PayloadCID: target("opaque JSON metadata")}
			for i := 0; i < p.Slots-1; i++ {
				state.Entries = append(state.Entries, engine.Entry{Label: coordinate.EncodeIndex(uint64(i)), Target: target(fmt.Sprint(i))})
			}
			root, err := e.Build(t.Context(), state, nodes)
			if err != nil {
				t.Fatal(err)
			}
			for _, n := range []int{p.Slots, p.Slots + 1} {
				value := target(fmt.Sprint(n - 1))
				root, _, err = e.Append(t.Context(), root, value, nodes, nodes)
				if err != nil {
					t.Fatal(err)
				}
				state.Entries = append(state.Entries, engine.Entry{Label: coordinate.EncodeIndex(uint64(n - 1)), Target: value})
				freshNodes := memory.NewNodes()
				fresh, err := e.Build(t.Context(), state, freshNodes)
				if err != nil || !root.Equals(fresh) {
					t.Fatalf("growth differs: %v", err)
				}
				if want := 2 + n - p.Slots; freshNodes.Len() != want {
					t.Fatalf("%d elements: %d vectors, want %d", n, freshNodes.Len(), want)
				}
				for _, index := range []uint64{0, uint64(p.Slots - 1), uint64(n - 1)} {
					result, err := e.Prove(t.Context(), root, coordinate.EncodeIndex(index), nodes)
					if err != nil {
						t.Fatal(err)
					}
					if len(result.Proof.Nodes) != 2 || len(result.Proof.Nodes[1].Metadata) != 0 || len(result.Proof.Nodes[1].MetadataProof) != 0 {
						t.Fatal("descendant reserves metadata")
					}
					ok, err := e.Verify(root, coordinate.EncodeIndex(index), result)
					if err != nil || !ok {
						t.Fatalf("proof: %v", err)
					}
					result.Proof.Nodes[1].Metadata = result.Proof.Nodes[0].Metadata
					if ok, _ := e.Verify(root, coordinate.EncodeIndex(index), result); ok {
						t.Fatal("internal metadata accepted")
					}
				}
			}
			for _, n := range []int{p.Slots, p.Slots - 1, 1, 0} {
				root, err = e.Truncate(t.Context(), root, uint64(n), nodes, nodes)
				if err != nil {
					t.Fatal(err)
				}
				state.Entries = state.Entries[:n]
				fresh, err := e.Build(t.Context(), state, memory.NewNodes())
				if err != nil || !root.Equals(fresh) {
					t.Fatalf("collapse %d: %v", n, err)
				}
				meta, _, err := e.ReadMetadata(t.Context(), root, nodes)
				if err != nil || meta.Count != uint64(n) || !meta.PayloadCID.Equals(state.PayloadCID) {
					t.Fatal("payload lost across height change", err)
				}
			}
			nodes.writes = 0
			root, err = e.SetPayload(t.Context(), root, cid.Undef, nodes, nodes)
			if err != nil || nodes.writes != 1 {
				t.Fatal("payload update should touch root only", err)
			}
			meta, _, err := e.ReadMetadata(t.Context(), root, nodes)
			if err != nil || meta.PayloadCID.Defined() {
				t.Fatal("payload not cleared")
			}
			end := uint64(1)
			if _, err = e.ProveRange(t.Context(), root, 0, &end, nodes); err == nil {
				t.Fatal("out of bounds range accepted")
			}
		})
	}
}

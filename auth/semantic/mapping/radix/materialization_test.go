package radix_test

import (
	"testing"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	materialmemory "github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/semantic/mapping"
	mappingradix "github.com/dewebprotocol/malt-core/auth/semantic/mapping/radix"
	cid "github.com/ipfs/go-cid"
)

func TestRadixMaterializationRoundTripUsesOnlyRootBoundProving(t *testing.T) {
	for name, factory := range mappingSchemes() {
		t.Run(name, func(t *testing.T) {
			scheme := factory(t)
			store := materialmemory.New(true)
			semantic, err := mappingradix.NewMap(scheme, store)
			if err != nil {
				t.Fatal(err)
			}
			view := mapping.NewViewFrom(map[string]cid.Cid{
				"@payload": fakeCID("materialization-payload"),
				"docs/a":   fakeCID("materialization-a"),
				"docs/b":   fakeCID("materialization-b"),
			})
			root, err := semantic.Commit(t.Context(), testNamespace, view)
			if err != nil {
				t.Fatal(err)
			}
			witness, err := semantic.ExportMaterialization(t.Context(), testNamespace, root, view)
			if err != nil {
				t.Fatal(err)
			}
			if witness.Len() == 0 {
				t.Fatal("exported radix materialization is empty")
			}
			prover, ok := scheme.(commitment.IndexRootProver)
			if !ok {
				t.Fatal("test commitment backend has no root-bound prover")
			}
			rootBound := &countingRootBoundVerifier{IndexVerifier: scheme, prover: prover}
			if err := mappingradix.ValidateMaterialization(t.Context(), rootBound, root, view, witness); err != nil {
				t.Fatalf("ValidateMaterialization failed: %v", err)
			}
			if rootBound.proves == 0 {
				t.Fatal("materialization validation did not call ProveAtRoot")
			}

			entries := witness.Entries()
			missing, err := arcset.NewCanonicalArcSet(arcset.KindMap, entries[1:])
			if err != nil {
				t.Fatal(err)
			}
			if err := mappingradix.ValidateMaterialization(t.Context(), rootBound, root, view, missing); err == nil {
				t.Fatal("materialization validation accepted a missing internal entry")
			}

			extraCoordinate, err := arcset.NewMapCoordinate("runtime/map/radix/unreachable")
			if err != nil {
				t.Fatal(err)
			}
			extra, err := arcset.NewCanonicalArcSet(arcset.KindMap, append(entries, arcset.ArcEntry{
				Coordinate: extraCoordinate, Target: arcset.NewUnknownTarget(fakeCID("unreachable")),
			}))
			if err != nil {
				t.Fatal(err)
			}
			if err := mappingradix.ValidateMaterialization(t.Context(), rootBound, root, view, extra); err == nil {
				t.Fatal("materialization validation accepted an unreachable internal entry")
			}

			wrongView := mapping.NewViewFrom(map[string]cid.Cid{
				"@payload": fakeCID("materialization-payload"),
				"docs/a":   fakeCID("tampered-a"),
				"docs/b":   fakeCID("materialization-b"),
			})
			if err := mappingradix.ValidateMaterialization(t.Context(), rootBound, root, wrongView, witness); err == nil {
				t.Fatal("materialization validation accepted the wrong logical view")
			}
		})
	}
}

type countingRootBoundVerifier struct {
	commitment.IndexVerifier
	prover commitment.IndexRootProver
	proves int
}

func (v *countingRootBoundVerifier) ProveAtRoot(root cid.Cid, values []commitment.Cell, index uint64) (commitment.Cell, []byte, error) {
	v.proves++
	return v.prover.ProveAtRoot(root, values, index)
}

func (v *countingRootBoundVerifier) BatchProveAtRoot(root cid.Cid, values []commitment.Cell, indices []uint64) ([]commitment.Cell, []byte, error) {
	return v.prover.BatchProveAtRoot(root, values, indices)
}

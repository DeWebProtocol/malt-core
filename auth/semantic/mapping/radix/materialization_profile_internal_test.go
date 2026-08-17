package radix

import (
	"context"
	"fmt"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	materialmemory "github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/semantic/mapping"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

func TestValidateMaterializationRejectsMixedVersionInternalNodeAcrossBackends(t *testing.T) {
	for name, scheme := range absenceSchemes(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			store := materialmemory.New(true)
			legacy, err := NewMapForVersion(scheme, store, maltcid.LegacyMALTVersionID)
			if err != nil {
				t.Fatal(err)
			}
			current, err := NewMap(scheme, store)
			if err != nil {
				t.Fatal(err)
			}
			var first arcset.Path
			var firstDigit, secondDigit uint64
			var second arcset.Path
			for index := 0; index < 100000 && second.IsEmpty(); index++ {
				candidate := arcset.CanonicalizePath(fmt.Sprintf("mixed-%d", index))
				digest := hashPath(candidate)
				digit0, ok0 := legacy.geometry.MapDigit(digest[:], 0)
				digit1, ok1 := legacy.geometry.MapDigit(digest[:], 1)
				if !ok0 || !ok1 {
					t.Fatal("missing radix digit")
				}
				if first.IsEmpty() {
					first, firstDigit, secondDigit = candidate, digit0, digit1
				} else if digit0 == firstDigit && digit1 != secondDigit {
					second = candidate
				}
			}
			if second.IsEmpty() {
				t.Fatal("failed to construct nested radix paths")
			}
			view := mapping.NewViewFromPaths(map[arcset.Path]cid.Cid{
				first:  bucketAbsenceValue(t, name+"-mixed-first"),
				second: bucketAbsenceValue(t, name+"-mixed-second"),
			})
			legacyRoot, err := legacy.Commit(ctx, name+"-mixed", view)
			if err != nil {
				t.Fatal(err)
			}
			legacyWitness, err := legacy.ExportMaterialization(ctx, name+"-mixed", legacyRoot, view)
			if err != nil {
				t.Fatal(err)
			}
			slots, err := legacy.loadNodeSlots(ctx, name+"-mixed", legacyRoot)
			if err != nil {
				t.Fatal(err)
			}
			if maltcid.VersionIDOf(slots[firstDigit]) != maltcid.LegacyMALTVersionID {
				t.Fatal("fixture has no nested v2 child")
			}
			mixedRoot, err := current.commitSlots(slots)
			if err != nil {
				t.Fatal(err)
			}
			entries := legacyWitness.Entries()
			for entryIndex := range entries {
				for slotIndex := range slots {
					if entries[entryIndex].Coordinate.String() != nodeSlotPath(legacyRoot, uint64(slotIndex)).String() {
						continue
					}
					coordinate, err := arcset.NewMapCoordinate(nodeSlotPath(mixedRoot, uint64(slotIndex)).String())
					if err != nil {
						t.Fatal(err)
					}
					entries[entryIndex].Coordinate = coordinate
				}
			}
			mixedWitness, err := arcset.NewCanonicalArcSet(arcset.KindMap, entries)
			if err != nil {
				t.Fatal(err)
			}
			rootBound, ok := scheme.(RootBoundVerifier)
			if !ok {
				t.Fatal("backend does not implement root-bound validation")
			}
			if err := ValidateMaterialization(ctx, rootBound, mixedRoot, view, mixedWitness); err == nil {
				t.Fatal("materialization validator accepted a v3 root with a v2 internal child")
			}
		})
	}
}

func TestMaterializationWalkerRejectsV1BucketUnderV3Root(t *testing.T) {
	scheme := absenceSchemes(t)["ipa"]
	rootBound, ok := scheme.(RootBoundVerifier)
	if !ok {
		t.Fatal("IPA backend does not implement root-bound validation")
	}
	maps, err := NewMap(scheme, materialmemory.New(true))
	if err != nil {
		t.Fatal(err)
	}
	paths := []arcset.Path{arcset.CanonicalizePath("a"), arcset.CanonicalizePath("z")}
	bindings := make([]leafBinding, len(paths))
	markers := make([]cid.Cid, len(paths))
	for index, path := range paths {
		bindings[index] = newLeafBinding(path, bucketAbsenceValue(t, "profile-"+path.String()))
		markers[index], err = encodeLeafMarker(path, bindings[index].value)
		if err != nil {
			t.Fatal(err)
		}
	}
	bucketRoot, err := maps.commitSlots(bucketVector(markers, scheme.MaxValues()))
	if err != nil {
		t.Fatal(err)
	}
	walker := &materializationWalker{
		ctx: context.Background(), scheme: rootBound, geometry: maps.geometry,
		version: maltcid.MALTVersionID, backend: maltcid.BackendKindIPA, expectedBucketVersion: bucketRefV2,
	}
	if err := walker.validateBucket(bucketRoot, bucketRefV1, bindings); err == nil {
		t.Fatal("materialization walker accepted a v1 bucket reference under a v3 root")
	}
}

package radix

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	materialmemory "github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
	"github.com/dewebprotocol/malt-core/auth/commitment/kzg"
	"github.com/dewebprotocol/malt-core/auth/semantic/mapping"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

func bucketAbsenceValue(t *testing.T, seed string) cid.Cid {
	t.Helper()
	hash, err := mh.Sum([]byte(seed), mh.SHA2_256, -1)
	if err != nil {
		t.Fatal(err)
	}
	return cid.NewCidV1(cid.Raw, hash)
}

func TestLoadBucketEntriesRejectsOversizedCountBeforeAllocation(t *testing.T) {
	scheme, err := ipa.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	store := materialmemory.New(true)
	maps, err := NewMap(scheme, store)
	if err != nil {
		t.Fatal(err)
	}
	root := bucketAbsenceValue(t, "hostile-bucket-root")
	count, err := encodeBucketCountMarker(math.MaxUint64)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := arcset.NewArcSetFromPaths(map[arcset.Path]cid.Cid{
		bucketCountPath(root): count,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Update(context.Background(), "hostile-bucket-count", cid.Undef, cid.Undef, snapshot); err != nil {
		t.Fatal(err)
	}
	if _, err := maps.loadBucketEntries(context.Background(), "hostile-bucket-count", root); err == nil {
		t.Fatal("oversized bucket count was accepted")
	}
}

func TestBucketAbsenceWitnessOpensCompleteCanonicalVector(t *testing.T) {
	scheme, err := ipa.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	maps, err := NewMap(scheme, materialmemory.New(true))
	if err != nil {
		t.Fatal(err)
	}
	paths := []arcset.Path{arcset.CanonicalizePath("a"), arcset.CanonicalizePath("z")}
	markers := make([]cid.Cid, len(paths))
	for index, path := range paths {
		markers[index], err = encodeLeafMarker(path, bucketAbsenceValue(t, path.String()))
		if err != nil {
			t.Fatal(err)
		}
	}
	root, err := scheme.Commit(cellsFromCIDs(bucketVector(markers, scheme.MaxValues())))
	if err != nil {
		t.Fatal(err)
	}
	absent := arcset.CanonicalizePath("m")
	witness, err := maps.proveBucketAbsence(root, markers, absent)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := maps.verifyBucketAbsence(root, absent, witness); err != nil || !ok {
		t.Fatalf("verify complete bucket absence = %v, %v", ok, err)
	}
	if ok, err := maps.verifyBucketAbsence(root, paths[0], witness); err != nil || ok {
		t.Fatalf("bucket witness proved present path absent = %v, %v", ok, err)
	}

	batchCopy := make([][]byte, len(witness.Batches))
	for index := range witness.Batches {
		batchCopy[index] = append([]byte(nil), witness.Batches[index]...)
	}
	reordered := &bucketWitness{
		Entries: append([][]byte(nil), witness.Entries...), Batches: batchCopy,
	}
	reordered.Entries[0], reordered.Entries[1] = reordered.Entries[1], reordered.Entries[0]
	if ok, err := maps.verifyBucketAbsence(root, absent, reordered); err != nil || ok {
		t.Fatalf("reordered bucket witness = %v, %v", ok, err)
	}

	truncated := &bucketWitness{
		Entries: append([][]byte(nil), witness.Entries[:1]...), Batches: batchCopy,
	}
	if ok, err := maps.verifyBucketAbsence(root, absent, truncated); err != nil || ok {
		t.Fatalf("truncated bucket witness = %v, %v", ok, err)
	}
}

func TestLegacyV1BucketMembershipAndNoOpUpdateRemainReadable(t *testing.T) {
	scheme, err := ipa.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	store := materialmemory.New(true)
	maps, err := NewMapForVersion(scheme, store, maltcid.LegacyMALTVersionID)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	namespace := "legacy-v1-bucket"
	paths := []arcset.Path{arcset.CanonicalizePath("a"), arcset.CanonicalizePath("z")}
	markers := make([]cid.Cid, len(paths))
	for index, path := range paths {
		markers[index], err = encodeLeafMarker(path, bucketAbsenceValue(t, "legacy-"+path.String()))
		if err != nil {
			t.Fatal(err)
		}
	}
	bucketRoot, err := maps.commitSlots(markers)
	if err != nil {
		t.Fatal(err)
	}
	bucketRef, err := encodeBucketRefVersion(bucketRoot, bucketRefV1)
	if err != nil {
		t.Fatal(err)
	}
	digest := hashPath(paths[0])
	slotIndex, ok := maps.geometry.MapDigit(digest[:], 0)
	if !ok {
		t.Fatal("missing radix digit")
	}
	slots := make([]cid.Cid, maps.geometry.NodeWidth())
	slots[slotIndex] = bucketRef
	root, err := maps.commitSlots(slots)
	if err != nil {
		t.Fatal(err)
	}
	if err := maps.storeBucketEntries(ctx, namespace, bucketRoot, markers); err != nil {
		t.Fatal(err)
	}
	if err := maps.storeNodeSlots(ctx, namespace, root, slots); err != nil {
		t.Fatal(err)
	}
	binding, proof, err := maps.Prove(ctx, namespace, root, paths[0])
	if err != nil {
		t.Fatal(err)
	}
	if !binding.Present {
		t.Fatal("legacy v1 bucket membership was reported absent")
	}
	if ok, err := maps.Verify(root, paths[0], binding, proof); err != nil || !ok {
		t.Fatalf("verify legacy v1 bucket membership = %v, %v", ok, err)
	}

	sameRef, nodes, buckets, err := maps.updateBucketWithoutPersist(ctx, namespace, bucketRoot, bucketRefV1, arcset.CanonicalizePath("missing"), cid.Undef, cid.Undef)
	if err != nil {
		t.Fatal(err)
	}
	if !sameRef.Equals(bucketRef) || len(nodes) != 0 || len(buckets) != 0 {
		t.Fatal("legacy v1 no-op update changed the bucket reference")
	}

	nextValue := bucketAbsenceValue(t, "legacy-replacement")
	updatedRef, _, pending, err := maps.updateBucketWithoutPersist(ctx, namespace, bucketRoot, bucketRefV1, paths[0], binding.Value, nextValue)
	if err != nil {
		t.Fatal(err)
	}
	_, version, ok, err := decodeBucketRef(updatedRef)
	if err != nil || !ok || version != bucketRefV1 || len(pending) != 1 {
		t.Fatalf("legacy bucket replay = version %d, decoded %v, buckets %d, err %v", version, ok, len(pending), err)
	}
}

func TestLegacyShortBucketRootDiffersFromFixedWidthRoot(t *testing.T) {
	schemes := map[string]commitment.IndexCommitment{}
	ipaScheme, err := ipa.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	schemes["ipa"] = ipaScheme
	kzgScheme, err := kzg.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	schemes["kzg"] = kzgScheme
	for name, scheme := range schemes {
		t.Run(name, func(t *testing.T) {
			markers := make([]cid.Cid, 2)
			for index, path := range []arcset.Path{arcset.CanonicalizePath("a"), arcset.CanonicalizePath("z")} {
				marker, err := encodeLeafMarker(path, bucketAbsenceValue(t, name+path.String()))
				if err != nil {
					t.Fatal(err)
				}
				markers[index] = marker
			}
			shortRoot, err := scheme.Commit(cellsFromCIDs(markers))
			if err != nil {
				t.Fatal(err)
			}
			paddedRoot, err := scheme.Commit(cellsFromCIDs(bucketVector(markers, scheme.MaxValues())))
			if err != nil {
				t.Fatal(err)
			}
			if shortRoot.Equals(paddedRoot) {
				t.Fatal("legacy short bucket root unexpectedly equals the v3 fixed-domain root")
			}
		})
	}
}

type commitCountingRootScheme struct {
	commitment.IndexCommitment
	rootProver commitment.IndexRootProver
	commits    int
}

func (s *commitCountingRootScheme) Commit(values []commitment.Cell) (cid.Cid, error) {
	s.commits++
	return s.IndexCommitment.Commit(values)
}

func (s *commitCountingRootScheme) ProveAtRoot(root cid.Cid, values []commitment.Cell, index uint64) (commitment.Cell, []byte, error) {
	return s.rootProver.ProveAtRoot(root, values, index)
}

func (s *commitCountingRootScheme) BatchProveAtRoot(root cid.Cid, values []commitment.Cell, indices []uint64) ([]commitment.Cell, []byte, error) {
	return s.rootProver.BatchProveAtRoot(root, values, indices)
}

func absenceSchemes(t *testing.T) map[string]commitment.IndexCommitment {
	t.Helper()
	ipaScheme, err := ipa.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	kzgScheme, err := kzg.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	return map[string]commitment.IndexCommitment{"ipa": ipaScheme, "kzg": kzgScheme}
}

func TestV2BucketMembershipOpensFixedDomainAcrossBackends(t *testing.T) {
	for name, scheme := range absenceSchemes(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			store := materialmemory.New(true)
			maps, err := NewMap(scheme, store)
			if err != nil {
				t.Fatal(err)
			}
			paths := []arcset.Path{arcset.CanonicalizePath("a"), arcset.CanonicalizePath("z")}
			markers := make([]cid.Cid, len(paths))
			for index, path := range paths {
				markers[index], err = encodeLeafMarker(path, bucketAbsenceValue(t, name+"-v2-"+path.String()))
				if err != nil {
					t.Fatal(err)
				}
			}
			bucketRoot, err := maps.commitSlots(bucketVector(markers, scheme.MaxValues()))
			if err != nil {
				t.Fatal(err)
			}
			bucketRef, err := encodeBucketRefVersion(bucketRoot, bucketRefV2)
			if err != nil {
				t.Fatal(err)
			}
			digest := hashPath(paths[0])
			slotIndex, ok := maps.geometry.MapDigit(digest[:], 0)
			if !ok {
				t.Fatal("missing radix digit")
			}
			slots := make([]cid.Cid, maps.geometry.NodeWidth())
			slots[slotIndex] = bucketRef
			root, err := maps.commitSlots(slots)
			if err != nil {
				t.Fatal(err)
			}
			if err := maps.storeBucketEntries(ctx, name+"-v2-bucket", bucketRoot, markers); err != nil {
				t.Fatal(err)
			}
			if err := maps.storeNodeSlots(ctx, name+"-v2-bucket", root, slots); err != nil {
				t.Fatal(err)
			}
			binding, proof, err := maps.Prove(ctx, name+"-v2-bucket", root, paths[0])
			if err != nil {
				t.Fatal(err)
			}
			if !binding.Present {
				t.Fatal("v2 bucket membership was reported absent")
			}
			if ok, err := maps.Verify(root, paths[0], binding, proof); err != nil || !ok {
				t.Fatalf("verify v2 bucket membership = %v, %v", ok, err)
			}
		})
	}
}

func TestLegacyV2TypedRootProvesWithoutCommitAcrossBackends(t *testing.T) {
	for name, backend := range absenceSchemes(t) {
		t.Run(name, func(t *testing.T) {
			rootProver, ok := backend.(commitment.IndexRootProver)
			if !ok {
				t.Fatal("backend does not implement IndexRootProver")
			}
			scheme := &commitCountingRootScheme{IndexCommitment: backend, rootProver: rootProver}
			store := materialmemory.New(true)
			maps, err := NewMapForVersion(scheme, store, 2)
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			path := arcset.CanonicalizePath("legacy")
			root, err := maps.Commit(ctx, name+"-legacy-v2", mapping.NewViewFromPaths(map[arcset.Path]cid.Cid{
				path: bucketAbsenceValue(t, name+"-legacy-value"),
			}))
			if err != nil {
				t.Fatal(err)
			}
			if got := maltcid.VersionIDOf(root); got != maltcid.LegacyMALTVersionID {
				t.Fatalf("root version = %d, want %d", got, maltcid.LegacyMALTVersionID)
			}
			scheme.commits = 0
			binding, proof, err := maps.Prove(ctx, name+"-legacy-v2", root, path)
			if err != nil {
				t.Fatal(err)
			}
			if !binding.Present || scheme.commits != 0 {
				t.Fatalf("binding present = %v, prove commits = %d", binding.Present, scheme.commits)
			}
			if ok, err := maps.Verify(root, path, binding, proof); err != nil || !ok {
				t.Fatalf("verify legacy v2 root = %v, %v", ok, err)
			}
		})
	}
}

func TestMutationRejectsLegacyRootBeforePartialVersionUpgradeAcrossBackends(t *testing.T) {
	for name, scheme := range absenceSchemes(t) {
		t.Run(name, func(t *testing.T) {
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
			var firstDigit uint64
			var secondDigit uint64
			found := false
			for index := 0; index < 100000 && !found; index++ {
				candidate := arcset.CanonicalizePath(fmt.Sprintf("nested-%d", index))
				digest := hashPath(candidate)
				digit0, ok0 := legacy.geometry.MapDigit(digest[:], 0)
				digit1, ok1 := legacy.geometry.MapDigit(digest[:], 1)
				if !ok0 || !ok1 {
					t.Fatal("missing radix digit")
				}
				if first.IsEmpty() {
					first, firstDigit, secondDigit = candidate, digit0, digit1
					continue
				}
				if digit0 == firstDigit && digit1 != secondDigit {
					values := map[arcset.Path]cid.Cid{
						first:     bucketAbsenceValue(t, name+"-legacy-first"),
						candidate: bucketAbsenceValue(t, name+"-legacy-second"),
					}
					root, err := legacy.Commit(context.Background(), name+"-legacy-nested", mapping.NewViewFromPaths(values))
					if err != nil {
						t.Fatal(err)
					}
					slots, err := legacy.loadNodeSlots(context.Background(), name+"-legacy-nested", root)
					if err != nil {
						t.Fatal(err)
					}
					if maltcid.VersionIDOf(root) != maltcid.LegacyMALTVersionID || maltcid.VersionIDOf(slots[firstDigit]) != maltcid.LegacyMALTVersionID {
						t.Fatal("fixture did not contain a nested v2 map node")
					}
					replacement := bucketAbsenceValue(t, name+"-replacement")
					if _, err := current.Update(context.Background(), name+"-legacy-nested", root, first, values[first], replacement); err == nil || !strings.Contains(err.Error(), "cannot be mutated") {
						t.Fatalf("Update legacy root error = %v", err)
					}
					if _, err := current.BatchUpdate(context.Background(), name+"-legacy-nested", root, []mapping.BatchUpdate{{
						Key: first, OldValue: values[first], NewValue: replacement,
					}}); err == nil || !strings.Contains(err.Error(), "cannot be mutated") {
						t.Fatalf("BatchUpdate legacy root error = %v", err)
					}
					found = true
				}
			}
			if !found {
				t.Fatal("failed to construct nested radix paths")
			}
		})
	}
}

func TestRuntimeVerifyRejectsV1BucketAbsenceUnderV3Root(t *testing.T) {
	scheme := absenceSchemes(t)["ipa"]
	maps, err := NewMap(scheme, materialmemory.New(true))
	if err != nil {
		t.Fatal(err)
	}
	paths := []arcset.Path{arcset.CanonicalizePath("a"), arcset.CanonicalizePath("z")}
	markers := make([]cid.Cid, len(paths))
	for index, path := range paths {
		markers[index], err = encodeLeafMarker(path, bucketAbsenceValue(t, "runtime-v1-"+path.String()))
		if err != nil {
			t.Fatal(err)
		}
	}
	bucketRoot, err := maps.commitSlots(bucketVector(markers, scheme.MaxValues()))
	if err != nil {
		t.Fatal(err)
	}
	bucketRef, err := encodeBucketRefVersion(bucketRoot, bucketRefV1)
	if err != nil {
		t.Fatal(err)
	}
	absent := arcset.CanonicalizePath("missing")
	digest := hashPath(absent)
	slotIndex, ok := maps.geometry.MapDigit(digest[:], 0)
	if !ok {
		t.Fatal("missing radix digit")
	}
	slots := make([]cid.Cid, maps.geometry.NodeWidth())
	slots[slotIndex] = bucketRef
	root, err := maps.commitSlots(slots)
	if err != nil {
		t.Fatal(err)
	}
	_, rootProof, err := maps.commitment.ProveSlot(root, slots, slotIndex)
	if err != nil {
		t.Fatal(err)
	}
	bucketWitness, err := maps.proveBucketAbsence(bucketRoot, markers, absent)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(proofEnvelope{
		Steps: []proofStep{{Slot: cidBytes(bucketRef), Proof: rootProof}}, Bucket: bucketWitness,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := maps.Verify(root, absent, mapping.Binding{Present: false}, encoded); err != nil || ok {
		t.Fatalf("v1 bucket absence under v3 root = %v, %v", ok, err)
	}
}

package verifier

import (
	"context"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	materialmemory "github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
	"github.com/dewebprotocol/malt-core/auth/commitment/kzg"
	"github.com/dewebprotocol/malt-core/auth/semantic/mapping"
	mappingradix "github.com/dewebprotocol/malt-core/auth/semantic/mapping/radix"
	"github.com/dewebprotocol/malt-core/auth/semantic/nodegeometry"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

func portableAbsenceCID(seed string) cid.Cid {
	sum, err := mh.Sum([]byte(seed), mh.SHA2_256, -1)
	if err != nil {
		panic(err)
	}
	return cid.NewCidV1(cid.Raw, sum)
}

func portableSharedFirstDigit(t *testing.T, geometry nodegeometry.Geometry, base arcset.Path) arcset.Path {
	t.Helper()
	baseDigest := sha256.Sum256([]byte(base.String()))
	baseDigit, ok := geometry.MapDigit(baseDigest[:], 0)
	if !ok {
		t.Fatal("base path has no first radix digit")
	}
	for index := 0; index < 1<<18; index++ {
		candidate := arcset.CanonicalizePath(fmt.Sprintf("portable-absent-%d", index))
		digest := sha256.Sum256([]byte(candidate.String()))
		if digit, ok := geometry.MapDigit(digest[:], 0); ok && digit == baseDigit && candidate != base {
			return candidate
		}
	}
	t.Fatal("could not find portable absence collision")
	return ""
}

func TestPortableRadixVerifierAcceptsRuntimeAbsenceProofs(t *testing.T) {
	factories := map[string]func(*testing.T) commitment.IndexCommitment{
		"kzg": func(t *testing.T) commitment.IndexCommitment {
			scheme, err := kzg.NewScheme()
			if err != nil {
				t.Fatal(err)
			}
			return scheme
		},
		"ipa": func(t *testing.T) commitment.IndexCommitment {
			scheme, err := ipa.NewScheme()
			if err != nil {
				t.Fatal(err)
			}
			return scheme
		},
	}
	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			scheme := factory(t)
			geometry, err := nodegeometry.ForCapacity(scheme.MaxValues())
			if err != nil {
				t.Fatal(err)
			}
			runtime, err := mappingradix.NewMap(scheme, materialmemory.New(true))
			if err != nil {
				t.Fatal(err)
			}
			portable := newRadixMapVerifier(scheme, geometry)
			ctx := context.Background()

			emptyNamespace := "portable-absence-empty-" + name
			emptyRoot, err := runtime.Commit(ctx, emptyNamespace, mapping.NewViewFrom(nil))
			if err != nil {
				t.Fatal(err)
			}
			emptyKey := arcset.CanonicalizePath("portable-empty-key")
			binding, proof, err := runtime.Prove(ctx, emptyNamespace, emptyRoot, emptyKey)
			if err != nil {
				t.Fatal(err)
			}
			if ok, err := portable.Verify(emptyRoot, emptyKey, binding, proof); err != nil || !ok {
				t.Fatalf("portable empty absence = %v, %v", ok, err)
			}

			presentKey := arcset.CanonicalizePath("portable-present")
			presentValue := portableAbsenceCID("portable-present-" + name)
			namespace := "portable-absence-leaf-" + name
			root, err := runtime.Commit(ctx, namespace, mapping.NewViewFromPaths(map[arcset.Path]cid.Cid{presentKey: presentValue}))
			if err != nil {
				t.Fatal(err)
			}
			absentKey := portableSharedFirstDigit(t, geometry, presentKey)
			binding, proof, err = runtime.Prove(ctx, namespace, root, absentKey)
			if err != nil {
				t.Fatal(err)
			}
			if ok, err := portable.Verify(root, absentKey, binding, proof); err != nil || !ok {
				t.Fatalf("portable conflicting-leaf absence = %v, %v", ok, err)
			}
		})
	}
}

func TestPortableRadixVerifierChecksCompleteBucketAbsence(t *testing.T) {
	scheme, err := ipa.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	geometry, err := nodegeometry.ForCapacity(scheme.MaxValues())
	if err != nil {
		t.Fatal(err)
	}
	paths := []arcset.Path{arcset.CanonicalizePath("a"), arcset.CanonicalizePath("z")}
	markers := make([]cid.Cid, len(paths))
	values := make([]commitment.Cell, scheme.MaxValues())
	entries := make([][]byte, len(paths))
	for index, path := range paths {
		markers[index], err = encodeRadixLeafMarker(path, portableAbsenceCID("bucket-"+path.String()))
		if err != nil {
			t.Fatal(err)
		}
		values[index] = commitment.CellFromCID(markers[index])
		entries[index] = markers[index].Bytes()
	}
	root, err := scheme.Commit(values)
	if err != nil {
		t.Fatal(err)
	}
	batches := make([][]byte, 0, (scheme.MaxValues()+radixBucketBatch-1)/radixBucketBatch)
	for start := 0; start < scheme.MaxValues(); start += radixBucketBatch {
		end := min(start+radixBucketBatch, scheme.MaxValues())
		indices := make([]uint64, end-start)
		for offset := range indices {
			indices[offset] = uint64(start + offset)
		}
		_, proof, err := scheme.BatchProveAtRoot(root, values, indices)
		if err != nil {
			t.Fatal(err)
		}
		batches = append(batches, proof)
	}
	verifier := &radixMapVerifier{scheme: scheme, geometry: geometry}
	witness := &radixBucketWitness{Entries: entries, Batches: batches}
	absent := arcset.CanonicalizePath("m")
	if ok, err := verifier.verifyBucketAbsence(root, absent, witness); err != nil || !ok {
		t.Fatalf("portable complete bucket absence = %v, %v", ok, err)
	}
	if ok, err := verifier.verifyBucketAbsence(root, paths[0], witness); err != nil || ok {
		t.Fatalf("portable bucket proved present key absent = %v, %v", ok, err)
	}
	tampered := &radixBucketWitness{Entries: append([][]byte(nil), entries...), Batches: append([][]byte(nil), batches...)}
	tampered.Entries[0], tampered.Entries[1] = tampered.Entries[1], tampered.Entries[0]
	if ok, err := verifier.verifyBucketAbsence(root, absent, tampered); err != nil || ok {
		t.Fatalf("portable reordered bucket witness = %v, %v", ok, err)
	}
}

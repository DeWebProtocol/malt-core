package kzg

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"runtime"
	"slices"
	"sync"
	"testing"

	blsfr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	gokzg4844 "github.com/crate-crypto/go-kzg-4844"
	"github.com/dewebprotocol/malt-core/auth/commitment"
)

func TestSparseOpeningsEqualDenseQuotients(t *testing.T) {
	scheme, err := NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	// Compare empty and occupied targets against the dense reference,
	// including both ends of the domain and a fully populated vector.
	for _, occupancy := range []int{0, 1, 2, 32, 127, 128, 129, 1024, MaxValues} {
		t.Run(fmt.Sprint(occupancy), func(t *testing.T) {
			polynomial := make([]blsfr.Element, MaxValues)
			for i := 0; i < occupancy; i++ {
				digest := sha256.Sum256([]byte(fmt.Sprintf("sparse-opening/%d/%d", occupancy, i)))
				polynomial[(i*73+19)%MaxValues].SetBytes(digest[:])
			}
			before := slices.Clone(polynomial)
			root, err := commitPolynomial(scheme.writerKey, polynomial)
			if err != nil {
				t.Fatal(err)
			}
			for _, index := range []uint64{0, 19, 2045, MaxValues - 1} {
				want, claimed, err := provePolynomialAtIndexDense(scheme.writerKey, scheme.domain, polynomial, index)
				if err != nil {
					t.Fatal(err)
				}
				got, value, err := provePolynomialAtIndex(scheme.writerKey, scheme.domain, polynomial, index)
				if err != nil {
					t.Fatal(err)
				}
				if got != want || value != claimed {
					t.Fatalf("different proof at %d", index)
				}
				if err := verifyKZGOpening(scheme.openingKey, root, scheme.domain.roots[index], value, got); err != nil {
					t.Fatal(err)
				}
			}
			if !slices.Equal(before, polynomial) {
				t.Fatal("opening mutated its input")
			}
		})
	}
}

func TestSparsePreparedOpeningConcurrentReuse(t *testing.T) {
	previous := runtime.GOMAXPROCS(1)
	t.Cleanup(func() { runtime.GOMAXPROCS(previous) })
	scheme, err := NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	cells := make([]commitment.Cell, MaxValues)
	for i := range 32 {
		cells[(i*73+19)%MaxValues] = commitment.NewCell([]byte(fmt.Sprint(i)))
	}
	root, err := scheme.Commit(cells)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := scheme.PrepareOpening(root, cells)
	if err != nil {
		t.Fatal(err)
	}
	indices := []uint64{0, 19, 92, 2045, MaxValues - 1}
	want := make([][]byte, len(indices))
	for i, index := range indices {
		_, want[i], err = prepared.Open(index)
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, budget := range []int{4, 1} {
		runtime.GOMAXPROCS(budget)
		var group sync.WaitGroup
		for i, index := range indices {
			group.Go(func() {
				cell, proof, err := prepared.Open(index)
				if err != nil || !bytes.Equal(proof, want[i]) {
					t.Errorf("Open(%d): unequal result, %v", index, err)
					return
				}
				if ok, err := scheme.VerifyIndex(root, index, cell, proof); err != nil || !ok {
					t.Errorf("VerifyIndex(%d): %v, %v", index, ok, err)
				}
			})
		}
		group.Wait()
	}
}

func TestSparseOpeningRejectsIncompleteInputs(t *testing.T) {
	scheme, err := NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	polynomial := make([]blsfr.Element, MaxValues)
	for _, call := range []func() (gokzg4844.KZGProof, gokzg4844.Scalar, error){
		func() (gokzg4844.KZGProof, gokzg4844.Scalar, error) {
			return provePolynomialAtIndex(nil, scheme.domain, polynomial, 0)
		},
		func() (gokzg4844.KZGProof, gokzg4844.Scalar, error) {
			return provePolynomialAtIndex(&kzgWriterKey{lagrangeG1: scheme.writerKey.lagrangeG1}, scheme.domain, polynomial, 0)
		},
		func() (gokzg4844.KZGProof, gokzg4844.Scalar, error) {
			return provePolynomialAtIndex(scheme.writerKey, nil, polynomial, 0)
		},
		func() (gokzg4844.KZGProof, gokzg4844.Scalar, error) {
			return provePolynomialAtIndex(scheme.writerKey, scheme.domain, polynomial[:MaxValues-1], 0)
		},
		func() (gokzg4844.KZGProof, gokzg4844.Scalar, error) {
			return provePolynomialAtIndex(scheme.writerKey, scheme.domain, polynomial, MaxValues)
		},
	} {
		if _, _, err := call(); err == nil {
			t.Fatal("incomplete opening inputs accepted")
		}
	}
	corrupt := bytes.Clone(trustedSetupOpeningBytes)
	corrupt[0] ^= 1
	if _, err := decodeG1Asset("unit openings", corrupt, trustedSetupOpeningsSHA256); err == nil {
		t.Fatal("corrupt auxiliary table accepted")
	}
}

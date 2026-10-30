package ipa_test

import (
	"bytes"
	"fmt"
	"runtime"
	"sync"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
)

func TestIPAParallelismPreservesCommitmentsAndOpenings(t *testing.T) {
	previous := runtime.GOMAXPROCS(1)
	t.Cleanup(func() { runtime.GOMAXPROCS(previous) })
	serial, err := ipa.NewCommitterScheme(ipa.ProfileDirect)
	if err != nil {
		t.Fatal(err)
	}
	indices := []uint64{0, ipa.MaxValues - 1}
	type fixture struct {
		name       string
		values     []commitment.Cell
		root       commitment.Value
		proof      []byte
		batchProof []byte
	}
	var fixtures []fixture
	for _, spec := range []struct {
		name  string
		count int
		start int
		step  int
	}{
		{"empty", 0, 0, 1},
		{"one_tail", 1, ipa.MaxValues - 1, 1},
		{"below_parallel_threshold", 15, 0, 1},
		{"at_parallel_threshold", 16, 0, 1},
		{"clustered_tail", 32, ipa.MaxValues - 32, 1},
		{"scattered", 32, 0, 8},
		{"full", ipa.MaxValues, 0, 1},
	} {
		f := fixture{name: spec.name, values: make([]commitment.Cell, ipa.MaxValues)}
		for n := 0; n < spec.count; n++ {
			i := spec.start + n*spec.step
			f.values[i] = commitment.NewCell([]byte(fmt.Sprintf("parallel-slot-%d", i)))
		}
		f.root, err = serial.Commit(f.values)
		if err != nil {
			t.Fatal(err)
		}
		_, f.proof, err = serial.Prove(f.root, f.values, indices[1])
		if err != nil {
			t.Fatal(err)
		}
		_, f.batchProof, err = serial.BatchProve(f.root, f.values, indices)
		if err != nil {
			t.Fatal(err)
		}
		fixtures = append(fixtures, f)
	}

	for _, profile := range []ipa.CommitterProfile{ipa.ProfileDirect, ipa.ProfileCompact, ipa.ProfileFast} {
		runtime.GOMAXPROCS(4)
		scheme, err := ipa.NewCommitterScheme(profile)
		if err != nil {
			t.Fatal(err)
		}
		// Reuse settings across budget changes, including a return to serial.
		for _, budget := range []int{1, 2, 4, 1} {
			runtime.GOMAXPROCS(budget)
			for _, f := range fixtures {
				t.Run(fmt.Sprintf("%s/cpus%d/%s", profile, budget, f.name), func(t *testing.T) {
					root, err := scheme.Commit(f.values)
					if err != nil || !root.Equals(f.root) {
						t.Fatalf("commitment differs from serial direct profile: %v", err)
					}
					value, proof, err := scheme.Prove(root, f.values, indices[1])
					if err != nil || !value.Equal(f.values[indices[1]]) || !bytes.Equal(proof, f.proof) {
						t.Fatalf("single proof differs from serial direct profile: %v", err)
					}
					values, batchProof, err := scheme.BatchProve(root, f.values, indices)
					if err != nil || !bytes.Equal(batchProof, f.batchProof) {
						t.Fatalf("batch proof differs from serial direct profile: %v", err)
					}
					if ok, err := serial.BatchVerify(root, indices, values, batchProof); err != nil || !ok {
						t.Fatalf("BatchVerify = %v, %v", ok, err)
					}
				})
			}
			f := fixtures[len(fixtures)-1]
			prepared, err := scheme.PrepareOpening(f.root, f.values)
			if err != nil {
				t.Fatal(err)
			}
			// Concurrent calls share immutable precomputation and the prepared
			// witness, but must not share MSM accumulators or folding buffers.
			var group sync.WaitGroup
			for range 3 {
				group.Go(func() {
					root, err := scheme.Commit(f.values)
					if err != nil || !root.Equals(f.root) {
						t.Errorf("%s cpus=%d concurrent Commit: %v", profile, budget, err)
					}
					value, proof, err := prepared.Open(indices[1])
					if err != nil || !value.Equal(f.values[indices[1]]) || !bytes.Equal(proof, f.proof) {
						t.Errorf("%s cpus=%d concurrent Open differs: %v", profile, budget, err)
					}
				})
			}
			group.Wait()
		}
	}
}

package kzg_test

import (
	"bytes"
	"runtime"
	"sync"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/commitment/kzg"
)

func TestKZGParallelismPreservesCommitmentsAndOpenings(t *testing.T) {
	previous := runtime.GOMAXPROCS(1)
	t.Cleanup(func() { runtime.GOMAXPROCS(previous) })
	scheme, err := kzg.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	values := compatibilityValues()
	wantRoot, err := scheme.Commit(values)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := scheme.PrepareOpening(wantRoot, values)
	if err != nil {
		t.Fatal(err)
	}
	indices := []uint64{0, 17, kzg.MaxValues - 1}
	wantProofs := make([][]byte, len(indices))
	for i, index := range indices {
		_, wantProofs[i], err = serial.Open(index)
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, budget := range []int{2, 6, 1} {
		runtime.GOMAXPROCS(budget)
		root, err := scheme.Commit(values)
		if err != nil {
			t.Fatal(err)
		}
		if !root.Equals(wantRoot) {
			t.Fatalf("GOMAXPROCS=%d changed the commitment", budget)
		}
		prepared, err := scheme.PrepareOpening(root, values)
		if err != nil {
			t.Fatal(err)
		}
		// Share one immutable prepared opening across concurrent callers. The
		// race detector also checks that parallel MSM does not mutate its key.
		var group sync.WaitGroup
		for i, index := range indices {
			group.Go(func() {
				value, proof, err := prepared.Open(index)
				if err != nil {
					t.Errorf("GOMAXPROCS=%d Open(%d): %v", budget, index, err)
					return
				}
				if !value.Equal(values[index]) || !bytes.Equal(proof, wantProofs[i]) {
					t.Errorf("GOMAXPROCS=%d changed opening %d", budget, index)
				}
				if ok, err := scheme.VerifyIndex(root, index, value, proof); err != nil || !ok {
					t.Errorf("GOMAXPROCS=%d VerifyIndex(%d) = %v, %v", budget, index, ok, err)
				}
			})
		}
		group.Wait()
	}
}

package commitment_test

import (
	"sync"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
	"github.com/dewebprotocol/malt-core/auth/commitment/kzg"
)

func TestPreparedRootOpenings(t *testing.T) {
	for _, backend := range []string{"kzg", "ipa"} {
		t.Run(backend, func(t *testing.T) {
			var scheme commitment.IndexCommitment
			var err error
			if backend == "kzg" {
				scheme, err = kzg.NewScheme()
			} else {
				scheme, err = ipa.NewScheme()
			}
			if err != nil {
				t.Fatal(err)
			}
			values := []commitment.Cell{commitment.NewCell([]byte("first")), commitment.NewCell([]byte("second"))}
			root, err := scheme.Commit(values)
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := scheme.(commitment.IndexRootOpener).PrepareOpeningAtRoot(root, values)
			if err != nil {
				t.Fatal(err)
			}
			if prepared.(commitment.SizedOpening).RetainedBytes() == 0 {
				t.Fatal("missing accounting")
			}
			values[0][0] ^= 1 // caller buffers must not alias the retained witness
			var wg sync.WaitGroup
			for i := 0; i < 4; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					cell, proof, err := prepared.Open(uint64(i % 2))
					if err != nil {
						t.Error(err)
						return
					}
					ok, err := scheme.VerifyIndex(root, uint64(i%2), cell, proof)
					if err != nil || !ok {
						t.Errorf("prepared proof: %v %v", ok, err)
					}
				}(i)
			}
			wg.Wait()
			corrupt, err := scheme.(commitment.IndexRootOpener).PrepareOpeningAtRoot(root, values)
			if err != nil {
				t.Fatal(err)
			}
			cell, proof, err := corrupt.Open(1)
			if err != nil {
				t.Fatal(err)
			}
			ok, _ := scheme.VerifyIndex(root, 1, cell, proof)
			if ok {
				t.Fatal("off-index corrupt vector verified")
			}
			if _, _, err := prepared.Open(2); err == nil {
				t.Fatal("out of range accepted")
			}
		})
	}
}

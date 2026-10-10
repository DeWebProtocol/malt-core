package tree

import (
	cid "github.com/ipfs/go-cid"
	"math"
	"math/big"
	"testing"
)

func TestPositionalGeometryUsesFullDescendants(t *testing.T) {
	for _, c := range []int{256, 4096} {
		counts := []uint64{0, 1, uint64(c - 1), uint64(c), uint64(c + 1), math.MaxUint64}
		limit := new(big.Int).SetUint64(uint64(c - 1))
		for limit.IsUint64() {
			n := limit.Uint64()
			counts = append(counts, n-1, n, n+1)
			limit.Mul(limit, big.NewInt(int64(c)))
		}
		for _, count := range counts {
			p := rootPosition(count, c)
			capacity := new(big.Int).Lsh(big.NewInt(int64(c-1)), p.height*radixBits(c))
			if capacity.Cmp(new(big.Int).SetUint64(count)) < 0 {
				t.Fatalf("capacity %d/%d", c, count)
			}
			if p.height > 0 && new(big.Int).Rsh(new(big.Int).Set(capacity), radixBits(c)).Cmp(new(big.Int).SetUint64(count)) >= 0 {
				t.Fatalf("nonminimal height %d/%d", c, count)
			}
			if count == 0 {
				continue
			}
			for _, index := range []uint64{0, count / 2, count - 1} {
				current, local := p, index
				for current.height > 0 {
					slot := current.slot(local, c)
					if slot < current.base() || slot >= c {
						t.Fatalf("slot %d/%d/%d", c, count, index)
					}
					next, start := current.child(slot-current.base(), c)
					local -= start
					if local >= next.count || next.root {
						t.Fatal("invalid child context")
					}
					current = next
				}
				if slot := current.slot(local, c); slot < current.base() || slot >= c {
					t.Fatal("invalid leaf slot")
				}
			}
		}
	}
}

func TestRootMetadataEncoding(t *testing.T) {
	for _, payload := range []cid.Cid{cid.Undef, cid.MustParse("bafkqaaa")} {
		original := Metadata{Count: math.MaxUint64, PayloadCID: payload}
		data := original.cell()
		if len(data) != 9+len(payload.Bytes()) {
			t.Fatal("redundant metadata fields")
		}
		decoded, err := parseMetadata(data)
		if err != nil || decoded != original {
			t.Fatalf("roundtrip: %v", err)
		}
		if _, err := parseMetadata(append(data, 0)); err == nil {
			t.Fatal("trailing metadata bytes accepted")
		}
	}
}

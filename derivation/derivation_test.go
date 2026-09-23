package derivation_test

import (
	"bytes"
	"encoding/hex"
	"math"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/coordinate"
	"github.com/dewebprotocol/malt-core/derivation"
)

func TestDirectCanonicalCoordinates(t *testing.T) {
	for _, index := range []uint64{0, 42, 1<<53 + 1, math.MaxUint64} {
		label := coordinate.EncodeIndex(index)
		got, err := derivation.Derive(derivation.Direct, label)
		if err != nil || got.Kind != coordinate.Index || got.Index != index {
			t.Fatalf("index %d: %v %v", index, got, err)
		}
		encoded, err := got.Encode()
		if err != nil || !bytes.Equal(encoded, label) {
			t.Fatal("Direct changed encoding", err)
		}
	}
	if hex.EncodeToString(coordinate.EncodeIndex(42)) != "000000000000002a" {
		t.Fatal("noncanonical index")
	}
	key := [32]byte{1, 2, 3}
	label := coordinate.EncodeKey(key)
	got, err := derivation.Derive(derivation.Direct, label)
	label[0] = 9
	if err != nil || got.Kind != coordinate.Key || got.Key != key {
		t.Fatal("Direct changed or retained key bytes", err)
	}
	for _, size := range []int{0, 1, 7, 9, 31, 33} {
		if _, err := derivation.Derive(derivation.Direct, make([]byte, size)); err == nil {
			t.Fatalf("accepted %d bytes", size)
		}
	}
	if _, err := derivation.Derive(derivation.Direct, []byte("42")); err == nil {
		t.Fatal("parsed text integer")
	}
}
func TestOpaqueLabelsAndUnsupportedProfiles(t *testing.T) {
	seen := map[coordinate.Coordinate]bool{}
	for _, label := range [][]byte{{}, []byte("@payload"), []byte("/a//b/"), []byte("a/b"), {0xff, 0, 47}} {
		got, err := derivation.Derive(derivation.SHA256, label)
		if err != nil || got.Kind != coordinate.Key || seen[got] {
			t.Fatal("label normalized or rejected", err)
		}
		seen[got] = true
	}
	for _, profile := range []derivation.ProfileID{0, 1, 2, 5, 255} {
		if _, err := derivation.Derive(profile, []byte("label")); err == nil {
			t.Fatal("unsupported profile accepted", profile)
		}
	}
}

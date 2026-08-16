package nodegeometry

import (
	"bytes"
	"testing"

	"github.com/dewebprotocol/malt-core/wire/maltcid"
)

func TestForCapacity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		capacity      int
		width         int
		radixBits     int
		mapDepth      int
		listBranching int
	}{
		{capacity: IPANodeWidth, width: 256, radixBits: 8, mapDepth: 32, listBranching: 255},
		{capacity: KZGNodeWidth, width: 4096, radixBits: 12, mapDepth: 22, listBranching: 4095},
	}
	for _, test := range tests {
		geometry, err := ForCapacity(test.capacity)
		if err != nil {
			t.Fatalf("ForCapacity(%d): %v", test.capacity, err)
		}
		if got := geometry.NodeWidth(); got != test.width {
			t.Fatalf("ForCapacity(%d).NodeWidth() = %d, want %d", test.capacity, got, test.width)
		}
		if got := geometry.MapRadixBits(); got != test.radixBits {
			t.Fatalf("ForCapacity(%d).MapRadixBits() = %d, want %d", test.capacity, got, test.radixBits)
		}
		if got := geometry.MapDepth(32); got != test.mapDepth {
			t.Fatalf("ForCapacity(%d).MapDepth(32) = %d, want %d", test.capacity, got, test.mapDepth)
		}
		if got := geometry.ListBranchingFactor(); got != test.listBranching {
			t.Fatalf("ForCapacity(%d).ListBranchingFactor() = %d, want %d", test.capacity, got, test.listBranching)
		}
	}
	if _, err := ForCapacity(1024); err == nil {
		t.Fatal("ForCapacity accepted an unregistered capacity")
	}
}

func TestForBackend(t *testing.T) {
	t.Parallel()

	tests := []struct {
		kind  maltcid.BackendKind
		width int
	}{
		{kind: maltcid.BackendKindIPA, width: IPANodeWidth},
		{kind: maltcid.BackendKindKZG, width: KZGNodeWidth},
	}
	for _, test := range tests {
		geometry, err := ForBackend(test.kind)
		if err != nil {
			t.Fatalf("ForBackend(%q): %v", test.kind, err)
		}
		if got := geometry.NodeWidth(); got != test.width {
			t.Fatalf("ForBackend(%q).NodeWidth() = %d, want %d", test.kind, got, test.width)
		}
	}
	if _, err := ForBackend(maltcid.BackendKindUnknown); err == nil {
		t.Fatal("ForBackend accepted an unknown backend")
	}
}

func TestKZGMapDigitsUseBigEndianTwelveBitStream(t *testing.T) {
	t.Parallel()

	geometry, err := ForCapacity(KZGNodeWidth)
	if err != nil {
		t.Fatal(err)
	}
	digest := make([]byte, 32)
	digest[0] = 0xab
	digest[1] = 0xcd
	digest[2] = 0xef
	digest[30] = 0x12
	digest[31] = 0x34

	tests := []struct {
		depth int
		want  uint64
	}{
		{depth: 0, want: 0xabc},
		{depth: 1, want: 0xdef},
		{depth: 20, want: 0x123},
		{depth: 21, want: 0x400},
	}
	for _, test := range tests {
		got, ok := geometry.MapDigit(digest, test.depth)
		if !ok {
			t.Fatalf("MapDigit(%d) rejected", test.depth)
		}
		if got != test.want {
			t.Fatalf("MapDigit(%d) = %#x, want %#x", test.depth, got, test.want)
		}
	}
	for _, depth := range []int{-1, 22} {
		if _, ok := geometry.MapDigit(digest, depth); ok {
			t.Fatalf("MapDigit accepted depth %d", depth)
		}
	}
}

func TestKZGMapDigitsCoverDigestExactlyOnce(t *testing.T) {
	t.Parallel()

	geometry, err := ForCapacity(KZGNodeWidth)
	if err != nil {
		t.Fatal(err)
	}
	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = byte(i*37 + 11)
	}
	var bits []byte
	for depth := 0; depth < geometry.MapDepth(len(digest)); depth++ {
		digit, ok := geometry.MapDigit(digest, depth)
		if !ok {
			t.Fatalf("MapDigit(%d) rejected", depth)
		}
		for bit := geometry.MapRadixBits() - 1; bit >= 0; bit-- {
			bits = append(bits, byte((digit>>uint(bit))&1))
		}
	}
	bits = bits[:len(digest)*8]
	reconstructed := make([]byte, len(digest))
	for i, bit := range bits {
		if bit != 0 {
			reconstructed[i/8] |= 1 << uint(7-i%8)
		}
	}
	if !bytes.Equal(reconstructed, digest) {
		t.Fatalf("reconstructed digest = %x, want %x", reconstructed, digest)
	}

	last, ok := geometry.MapDigit(digest, 21)
	if !ok {
		t.Fatal("last MapDigit rejected")
	}
	if want := uint64(digest[31]&0x0f) << 8; last != want {
		t.Fatalf("last MapDigit = %#x, want %#x", last, want)
	}
}

func TestListGeometryBoundaries(t *testing.T) {
	t.Parallel()

	for _, capacity := range []int{IPANodeWidth, KZGNodeWidth} {
		geometry, err := ForCapacity(capacity)
		if err != nil {
			t.Fatal(err)
		}
		branching := uint64(geometry.ListBranchingFactor())
		if got := geometry.RequiredListHeight(branching); got != 0 {
			t.Fatalf("capacity %d height at branching = %d, want 0", capacity, got)
		}
		if got := geometry.RequiredListHeight(branching + 1); got != 1 {
			t.Fatalf("capacity %d height above branching = %d, want 1", capacity, got)
		}
		digits, err := geometry.ListIndexDigits(branching, 1)
		if err != nil {
			t.Fatalf("capacity %d ListIndexDigits: %v", capacity, err)
		}
		if len(digits) != 2 || digits[0] != 1 || digits[1] != 0 {
			t.Fatalf("capacity %d digits = %v, want [1 0]", capacity, digits)
		}
	}
}

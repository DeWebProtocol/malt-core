// Package nodegeometry defines the backend-sized physical node geometry shared
// by semantic producers and storage-free verifiers.
package nodegeometry

import (
	"fmt"
	"math"

	"github.com/dewebprotocol/malt-core/wire/maltcid"
)

const (
	// IPANodeWidth is the physical node width of the current IPA suite.
	IPANodeWidth = 256
	// KZGNodeWidth is the physical node width of the current KZG suite.
	KZGNodeWidth = 4096
)

// Geometry describes the physical node width and map radix associated with one
// commitment backend suite.
type Geometry struct {
	nodeWidth    int
	mapRadixBits int
}

// ForCapacity returns the semantic geometry locked to a registered commitment
// suite's maximum vector capacity.
func ForCapacity(capacity int) (Geometry, error) {
	switch capacity {
	case IPANodeWidth:
		return Geometry{nodeWidth: IPANodeWidth, mapRadixBits: 8}, nil
	case KZGNodeWidth:
		return Geometry{nodeWidth: KZGNodeWidth, mapRadixBits: 12}, nil
	default:
		return Geometry{}, fmt.Errorf("unsupported commitment capacity %d", capacity)
	}
}

// ForBackend returns the semantic geometry locked to a typed-root commitment
// backend suite.
func ForBackend(kind maltcid.BackendKind) (Geometry, error) {
	switch kind {
	case maltcid.BackendKindIPA:
		return ForCapacity(IPANodeWidth)
	case maltcid.BackendKindKZG:
		return ForCapacity(KZGNodeWidth)
	default:
		return Geometry{}, fmt.Errorf("unsupported commitment backend %q", kind)
	}
}

// NodeWidth returns the number of physical commitment slots in every semantic
// map or list node.
func (g Geometry) NodeWidth() int {
	return g.nodeWidth
}

// MapRadixBits returns the number of digest bits consumed by one map level.
func (g Geometry) MapRadixBits() int {
	return g.mapRadixBits
}

// MapDepth returns the number of radix digits needed to consume byteLength
// bytes. The final digit is right-padded with zero bits when necessary.
func (g Geometry) MapDepth(byteLength int) int {
	if byteLength <= 0 || g.mapRadixBits <= 0 {
		return 0
	}
	return (byteLength*8 + g.mapRadixBits - 1) / g.mapRadixBits
}

// MapDigit reads one radix digit from a big-endian bit stream. If the final
// digit is partial, its remaining low bits are zero-filled.
func (g Geometry) MapDigit(digest []byte, depth int) (uint64, bool) {
	if depth < 0 || depth >= g.MapDepth(len(digest)) {
		return 0, false
	}

	startBit := depth * g.mapRadixBits
	var digit uint64
	for offset := 0; offset < g.mapRadixBits; offset++ {
		digit <<= 1
		bit := startBit + offset
		if bit >= len(digest)*8 {
			continue
		}
		digit |= uint64((digest[bit/8] >> (7 - uint(bit%8))) & 1)
	}
	return digit, true
}

// ListBranchingFactor returns the number of data-bearing slots in a list node.
// Slot zero is reserved for authenticated metadata.
func (g Geometry) ListBranchingFactor() int {
	if g.nodeWidth <= 0 {
		return 0
	}
	return g.nodeWidth - 1
}

// RequiredListHeight returns the minimal non-root height required for length
// values.
func (g Geometry) RequiredListHeight(length uint64) int {
	branching := uint64(g.ListBranchingFactor())
	if branching == 0 || length <= branching {
		return 0
	}

	capacity := branching
	height := 0
	for capacity < length {
		height++
		if capacity > math.MaxUint64/branching {
			return height
		}
		capacity *= branching
	}
	return height
}

// ListSubtreeCapacity returns how many values fit under a list node of height.
func (g Geometry) ListSubtreeCapacity(height int) (uint64, error) {
	if height < 0 {
		return 0, fmt.Errorf("height must be non-negative")
	}
	branching := uint64(g.ListBranchingFactor())
	if branching == 0 {
		return 0, fmt.Errorf("list branching factor is zero")
	}

	capacity := branching
	for i := 0; i < height; i++ {
		if capacity > math.MaxUint64/branching {
			return 0, fmt.Errorf("list capacity overflow at height %d", height)
		}
		capacity *= branching
	}
	return capacity, nil
}

// ListIndexDigits decomposes an index into base-branching-factor digits for
// the target list height.
func (g Geometry) ListIndexDigits(index uint64, height int) ([]int, error) {
	if height < 0 {
		return nil, fmt.Errorf("height must be non-negative")
	}

	digits := make([]int, height+1)
	remaining := index
	for level := 0; level <= height; level++ {
		exp := height - level
		if exp == 0 {
			if remaining >= uint64(g.ListBranchingFactor()) {
				return nil, fmt.Errorf("index digit %d exceeds branching factor %d", remaining, g.ListBranchingFactor())
			}
			digits[level] = int(remaining)
			continue
		}
		chunk, err := g.ListSubtreeCapacity(exp - 1)
		if err != nil {
			return nil, err
		}
		digit := remaining / chunk
		if digit >= uint64(g.ListBranchingFactor()) {
			return nil, fmt.Errorf("index digit %d exceeds branching factor %d", digit, g.ListBranchingFactor())
		}
		digits[level] = int(digit)
		remaining %= chunk
	}
	return digits, nil
}

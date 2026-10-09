package tree

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/bits"

	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/maltcid"
	cid "github.com/ipfs/go-cid"
)

// Metadata is authenticated only at the Positional root. PayloadCID is an
// optional opaque application-content reference; the tree never decodes it.
type Metadata struct {
	Count      uint64  `json:"count,string"`
	PayloadCID cid.Cid `json:"payload_cid" schema:"optional,nullable"`
}

func (m Metadata) cell() commitment.Cell {
	data := binary.BigEndian.AppendUint64(commitment.Cell{metadataCell}, m.Count)
	return append(data, m.PayloadCID.Bytes()...)
}

func parseMetadata(data commitment.Cell) (Metadata, error) {
	if len(data) < 9 || data[0] != metadataCell {
		return Metadata{}, errors.New("invalid Positional root metadata")
	}
	m := Metadata{Count: binary.BigEndian.Uint64(data[1:9])}
	if len(data) > 9 {
		var err error
		m.PayloadCID, err = cid.Cast(data[9:])
		if err != nil || !bytes.Equal(m.PayloadCID.Bytes(), data[9:]) {
			return Metadata{}, errors.New("invalid metadata payload CID")
		}
	}
	return m, nil
}

// position is traversal context, never serialized in an internal node. A root
// has C-1 content slots; every descendant has C. Height zero denotes a leaf.
type position struct {
	count  uint64
	height uint
	root   bool
}

func rootPosition(count uint64, slots int) position {
	p := position{count: count, root: true}
	if count > 0 {
		for high := count - 1; high >= uint64(slots-1); high >>= radixBits(slots) {
			p.height++
		}
	}
	return p
}

func radixBits(slots int) uint { return uint(bits.TrailingZeros(uint(slots))) }
func (p position) base() int {
	if p.root {
		return 1
	}
	return 0
}
func (p position) shift(slots int) uint { return p.height * radixBits(slots) }
func (p position) slot(index uint64, slots int) int {
	return p.base() + int(index>>p.shift(slots))
}
func (p position) used(slots int) int {
	if p.count == 0 {
		return 0
	}
	return int((p.count-1)>>p.shift(slots)) + 1
}

// child handles a virtual span of 2^64 without overflowing uint64. A selected
// child's start is always representable because it lies below count.
func (p position) child(digit int, slots int) (position, uint64) {
	shift := p.shift(slots)
	start := uint64(digit) << shift
	count := p.count - start
	if shift < 64 {
		count = min(count, uint64(1)<<shift)
	}
	return position{count: count, height: p.height - 1}, start
}

func (b *builder) positional(items []binding, meta Metadata) (maltcid.NodeRef, error) {
	return b.positionalNode(items, rootPosition(meta.Count, b.profile.Slots), meta)
}

func (b *builder) positionalNode(items []binding, p position, meta Metadata) (maltcid.NodeRef, error) {
	cells := make([]commitment.Cell, b.profile.Slots)
	if p.root {
		cells[0] = meta.cell()
	}
	if p.height == 0 {
		for i, item := range items {
			cells[p.base()+i] = append(commitment.Cell{positionalLeaf}, item.target.Bytes()...)
		}
	} else {
		for digit := 0; digit < p.used(b.profile.Slots); digit++ {
			child, start := p.child(digit, b.profile.Slots)
			ref, err := b.positionalNode(items[start:start+child.count], child, Metadata{})
			if err != nil {
				return maltcid.NodeRef{}, err
			}
			cells[p.base()+digit], err = childCell(ref)
			if err != nil {
				return maltcid.NodeRef{}, err
			}
		}
	}
	return b.commit(cells)
}

// checkPosition validates shape using authenticated parent context. Internal
// metadata, holes, wrong cell roles and nonempty padding are all noncanonical.
func checkPosition(cells []commitment.Cell, p position, slots int) error {
	if len(cells) != slots || p.used(slots) > slots-p.base() {
		return errors.New("invalid Positional node geometry")
	}
	for slot := p.base(); slot < slots; slot++ {
		cell := cells[slot]
		if slot-p.base() >= p.used(slots) {
			if len(cell) != 0 {
				return errors.New("nonempty Positional padding")
			}
			continue
		}
		want := childNode
		if p.height == 0 {
			want = positionalLeaf
		}
		if len(cell) == 0 || cell[0] != want {
			return errors.New("invalid Positional content cell")
		}
	}
	return nil
}

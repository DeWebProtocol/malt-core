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

// Metadata is authenticated only at the List root. PayloadCID is an
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
		return Metadata{}, errors.New("invalid List root metadata")
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

// listGeometry is authenticated List traversal context, never serialized in an internal node. A root
// has C-1 content slots; every descendant has C. Height zero denotes a leaf.
type listGeometry struct {
	count  uint64
	height uint
	root   bool
}

func listRootGeometry(count uint64, slots int) listGeometry {
	p := listGeometry{count: count, root: true}
	if count > 0 {
		for high := count - 1; high >= uint64(slots-1); high >>= listRadixBits(slots) {
			p.height++
		}
	}
	return p
}

func listRadixBits(slots int) uint { return uint(bits.TrailingZeros(uint(slots))) }
func (p listGeometry) base() int {
	if p.root {
		return 1
	}
	return 0
}
func (p listGeometry) shift(slots int) uint { return p.height * listRadixBits(slots) }
func (p listGeometry) slot(index uint64, slots int) int {
	return p.base() + int(index>>p.shift(slots))
}
func (p listGeometry) used(slots int) int {
	if p.count == 0 {
		return 0
	}
	return int((p.count-1)>>p.shift(slots)) + 1
}

// child handles a virtual span of 2^64 without overflowing uint64. A selected
// child's start is always representable because it lies below count.
func (p listGeometry) child(digit int, slots int) (listGeometry, uint64) {
	shift := p.shift(slots)
	start := uint64(digit) << shift
	count := p.count - start
	if shift < 64 {
		count = min(count, uint64(1)<<shift)
	}
	return listGeometry{count: count, height: p.height - 1}, start
}

func (b *builder) list(items []binding, meta Metadata) (maltcid.NodeRef, error) {
	return b.listNode(items, listRootGeometry(meta.Count, b.profile.Slots), meta)
}

func (b *builder) listNode(items []binding, p listGeometry, meta Metadata) (maltcid.NodeRef, error) {
	cells := make([]commitment.Cell, b.profile.Slots)
	if p.root {
		cells[0] = meta.cell()
	}
	if p.height == 0 {
		for i, item := range items {
			cells[p.base()+i] = append(commitment.Cell{listLeaf}, item.target.Bytes()...)
		}
	} else {
		for digit := 0; digit < p.used(b.profile.Slots); digit++ {
			child, start := p.child(digit, b.profile.Slots)
			ref, err := b.listNode(items[start:start+child.count], child, Metadata{})
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

// checkListGeometry validates shape using authenticated parent context. Internal
// metadata, holes, wrong cell roles and nonempty padding are all noncanonical.
func checkListGeometry(cells []commitment.Cell, p listGeometry, slots int) error {
	if len(cells) != slots || p.used(slots) > slots-p.base() {
		return errors.New("invalid List node geometry")
	}
	for slot := p.base(); slot < slots; slot++ {
		cell := cells[slot]
		if slot-p.base() >= p.used(slots) {
			if len(cell) != 0 {
				return errors.New("nonempty List padding")
			}
			continue
		}
		want := childNode
		if p.height == 0 {
			want = listLeaf
		}
		if len(cell) == 0 || cell[0] != want {
			return errors.New("invalid List content cell")
		}
	}
	return nil
}

func parseList(cell commitment.Cell) (cid.Cid, error) {
	if len(cell) < 2 || cell[0] != listLeaf {
		return cid.Undef, errors.New("invalid List target")
	}
	target, err := cid.Cast(cell[1:])
	if err != nil {
		return cid.Undef, err
	}
	if !bytes.Equal(target.Bytes(), cell[1:]) {
		return cid.Undef, errors.New("noncanonical List target")
	}
	return target, nil
}

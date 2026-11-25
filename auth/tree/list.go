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
	tail   bool // this interval ends at the highest bound index
}

func listRootGeometry(count uint64, slots int) listGeometry {
	p := listGeometry{count: count, root: true, tail: true}
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
	return listGeometry{count: count, height: p.height - 1, tail: p.tail && digit == p.used(slots)-1}, start
}

func (b *builder) list(items []binding, meta Metadata) (maltcid.NodeRef, error) {
	return b.listNode(items, listRootGeometry(meta.Count, b.profile.Slots), 0, meta)
}

func (b *builder) listNode(items []binding, p listGeometry, offset uint64, meta Metadata) (maltcid.NodeRef, error) {
	cells := make([]commitment.Cell, b.profile.Slots)
	if p.root {
		cells[0] = meta.cell()
	}
	if p.height == 0 {
		for _, item := range items {
			cells[p.slot(item.coordinate.Index-offset, len(cells))] = append(commitment.Cell{listLeaf}, item.target.Bytes()...)
		}
	} else {
		for len(items) > 0 {
			slot := p.slot(items[0].coordinate.Index-offset, len(cells))
			n := 1
			for n < len(items) && p.slot(items[n].coordinate.Index-offset, len(cells)) == slot {
				n++
			}
			child, start := p.child(slot-p.base(), len(cells))
			ref, err := b.listNode(items[:n], child, offset+start, Metadata{})
			if err != nil {
				return maltcid.NodeRef{}, err
			}
			cells[slot] = childCell(ref.Commitment)
			items = items[n:]
		}
	}
	return b.commit(cells)
}

// checkListGeometry validates shape using authenticated parent context. Internal
// metadata, fully empty descendants and nonempty padding are noncanonical.
func checkListGeometry(cells []commitment.Cell, p listGeometry, slots int) error {
	if len(cells) != slots || p.used(slots) > slots-p.base() {
		return errors.New("invalid List node geometry")
	}
	occupied := false
	for slot := p.base(); slot < slots; slot++ {
		cell := cells[slot]
		if len(cell) == 0 {
			if p.tail && slot-p.base() == p.used(slots)-1 {
				return errors.New("List count extends past its last binding")
			}
			continue
		}
		occupied = true
		if slot-p.base() >= p.used(slots) {
			return errors.New("nonempty List padding")
		}
		want := childNode
		if p.height == 0 {
			want = listLeaf
		}
		if cell[0] != want {
			return errors.New("invalid List content cell")
		}
	}
	if !p.root && !occupied {
		return errors.New("empty List subtree must be an empty cell")
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

package tree

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/maltcid"
	cid "github.com/ipfs/go-cid"
)

// Map routes original-label bindings through coordinate digits. A slot is
// empty, a label-bound leaf, or a child vector when multiple keys share a digit.
func mapCell(item binding) commitment.Cell {
	cell := binary.AppendUvarint(commitment.Cell{mapLeaf}, uint64(len(item.label)))
	cell = append(cell, item.label...)
	return append(cell, item.target.Bytes()...)
}
func parseMap(cell commitment.Cell) ([]byte, cid.Cid, error) {
	if len(cell) < 3 || cell[0] != mapLeaf {
		return nil, cid.Undef, errors.New("invalid Map leaf")
	}
	size, n := binary.Uvarint(cell[1:])
	if n <= 0 || n > 9 || len(binary.AppendUvarint(nil, size)) != n || size >= uint64(len(cell)-1-n) {
		return nil, cid.Undef, errors.New("invalid or noncanonical Map label length")
	}
	end := 1 + n + int(size)
	label := append([]byte{}, cell[1+n:end]...)
	target, err := cid.Cast(cell[end:])
	if err != nil {
		return nil, cid.Undef, err
	}
	if !bytes.Equal(target.Bytes(), cell[end:]) {
		return nil, cid.Undef, errors.New("noncanonical target")
	}
	return label, target, nil
}
func mapSlot(key [32]byte, depth, slots int) (int, error) {
	bits := 0
	for n := slots; n > 1; n >>= 1 {
		bits++
	}
	if slots < 2 || 1<<bits != slots || depth < 0 || depth*bits >= 256 {
		return 0, errors.New("invalid Map geometry or depth")
	}
	value := 0
	for i := 0; i < bits; i++ {
		value <<= 1
		bit := depth*bits + i
		if bit < 256 {
			value |= int((key[bit/8] >> uint(7-bit%8)) & 1)
		}
	}
	return value, nil
}
func (b *builder) mapNode(items []binding, depth int) (maltcid.NodeRef, error) {
	cells := make([]commitment.Cell, b.profile.Slots)
	groups := make(map[int][]binding)
	for _, item := range items {
		d, err := mapSlot(item.coordinate.Key, depth, b.profile.Slots)
		if err != nil {
			return maltcid.NodeRef{}, err
		}
		groups[d] = append(groups[d], item)
	}
	// Deterministic traversal also makes materialization ordering reproducible.
	for i := range cells {
		group := groups[i]
		if len(group) == 1 {
			cells[i] = mapCell(group[0])
		} else if len(group) > 1 {
			ref, err := b.mapNode(group, depth+1)
			if err != nil {
				return maltcid.NodeRef{}, err
			}
			cells[i], err = childCell(ref)
			if err != nil {
				return maltcid.NodeRef{}, err
			}
		}
	}
	return b.commit(cells)
}
func checkMapRoute(leaf, query [32]byte, depth, slots int) error {
	for d := 0; d <= depth; d++ {
		a, err := mapSlot(leaf, d, slots)
		if err != nil {
			return err
		}
		b, _ := mapSlot(query, d, slots)
		if a != b {
			return errors.New("leaf does not match its routing prefix")
		}
	}
	return nil
}

package tree

import (
	"bytes"
	"sort"

	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/maltcid"
)

func (u *nodeEdit) mapNode(b *builder, ref maltcid.NodeRef, depth int, items []coordinateChange) ([]commitment.Cell, error) {
	cells, err := u.GetNode(u.ctx, ref)
	if err != nil {
		return nil, err
	}
	groups := make(map[int][]coordinateChange)
	for _, item := range items {
		slot, err := mapSlot(item.key.Key, depth, u.profile.Slots)
		if err != nil {
			return nil, err
		}
		groups[slot] = append(groups[slot], item)
	}
	for slot := range cells {
		group := groups[slot]
		if len(group) == 0 {
			continue
		}
		old := cells[slot]
		if len(old) > 0 && old[0] == childNode {
			child, err := parseChild(old, ref)
			if err != nil {
				return nil, err
			}
			next, err := u.mapNode(b, child, depth+1, group)
			if err != nil {
				return nil, err
			}
			var only commitment.Cell
			count := 0
			for _, cell := range next {
				if len(cell) > 0 {
					only = cell
					count++
				}
			}
			switch {
			case count == 0:
				cells[slot] = nil
			case count == 1 && only[0] == mapLeaf:
				cells[slot] = only
			default:
				child, err = b.commit(next)
				if err != nil {
					return nil, err
				}
				cells[slot], err = childCell(child)
				if err != nil {
					return nil, err
				}
			}
			continue
		}
		entries := make(map[[32]byte]binding)
		if len(old) > 0 {
			label, target, err := parseMap(old)
			if err != nil {
				return nil, err
			}
			key, err := u.tree.labelCoordinate(u.descriptor, label)
			if err != nil {
				return nil, err
			}
			if err := checkMapRoute(key.Key, group[0].key.Key, depth, u.profile.Slots); err != nil {
				return nil, err
			}
			entries[key.Key] = binding{coordinate: key, label: label, target: target}
		}
		for _, item := range group {
			actual, exists := entries[item.key.Key]
			if exists && !bytes.Equal(actual.label, item.label) {
				return nil, ErrCoordinateCollision
			}
			if err := expect(actual.target, item); err != nil {
				return nil, err
			}
			if item.after.Defined() {
				entries[item.key.Key] = binding{coordinate: item.key, label: item.label, target: item.after}
			} else {
				delete(entries, item.key.Key)
			}
		}
		bindings := make([]binding, 0, len(entries))
		for _, entry := range entries {
			bindings = append(bindings, entry)
		}
		sort.Slice(bindings, func(i, j int) bool {
			return bytes.Compare(bindings[i].coordinate.Key[:], bindings[j].coordinate.Key[:]) < 0
		})
		switch len(bindings) {
		case 0:
			cells[slot] = nil
		case 1:
			cells[slot] = mapCell(bindings[0])
		default:
			child, err := b.mapNode(bindings, depth+1)
			if err != nil {
				return nil, err
			}
			cells[slot], err = childCell(child)
			if err != nil {
				return nil, err
			}
		}
	}
	return cells, nil
}

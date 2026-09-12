package maltcid

import (
	"fmt"
	cid "github.com/ipfs/go-cid"
)

// Cell tags belong to the V=0 node encoding selected by the layout. Empty
// vectors use empty bytes, not another application target or internal Root.
const (
	PrefixLeafCell     byte = 1
	ChildNodeCell      byte = 2
	PositionalLeafCell byte = 3
	MetadataCell       byte = 4
)

// CellReference decodes the references needed to retain already-authenticated
// materialization. This is not proof verification and does not establish trust.
func CellReference(cell []byte) (*NodeRef, cid.Cid, error) {
	if len(cell) == 0 {
		return nil, cid.Undef, nil
	}
	switch cell[0] {
	case ChildNodeCell:
		r, err := ParseNodeRef(cell[1:])
		return &r, cid.Undef, err
	case PrefixLeafCell:
		if len(cell) <= 33 {
			return nil, cid.Undef, fmt.Errorf("invalid Prefix leaf")
		}
		target, err := cid.Cast(cell[33:])
		return nil, target, err
	case PositionalLeafCell:
		target, err := cid.Cast(cell[1:])
		return nil, target, err
	case MetadataCell:
		return nil, cid.Undef, nil
	default:
		return nil, cid.Undef, fmt.Errorf("unknown node Cell tag")
	}
}

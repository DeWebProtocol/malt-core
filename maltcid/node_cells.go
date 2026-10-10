package maltcid

// Cell tags belong to the V=0 node encoding selected by the layout. Empty
// vectors use empty bytes, not another application target or internal Root.
const (
	// PrefixLeafCell frames label length, original label bytes and target CID
	// under Prefix layout 4. Coordinate-only layout 1 is not accepted.
	PrefixLeafCell     byte = 1
	ChildNodeCell      byte = 2
	PositionalLeafCell byte = 3
	MetadataCell       byte = 4
)

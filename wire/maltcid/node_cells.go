package maltcid

// Cell tags belong to the V=0 node encoding selected by the layout. Empty
// vectors use empty bytes, not another application target or internal Root.
const (
	PrefixLeafCell     byte = 1
	ChildNodeCell      byte = 2
	PositionalLeafCell byte = 3
	MetadataCell       byte = 4
)

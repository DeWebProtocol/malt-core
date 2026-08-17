package commitment

import (
	"github.com/dewebprotocol/malt-core/auth/arcset"
	cid "github.com/ipfs/go-cid"
)

// ExtractSortedPathsValues extracts sorted paths and values from an arc set.
// This is used when higher layers need a deterministic path-to-index mapping.
func ExtractSortedPathsValues(arcs arcset.ArcSet) ([]string, []cid.Cid) {
	var paths []string
	iter := arcs.Iterate()
	for {
		path, _, ok := iter.Next()
		if !ok {
			break
		}
		paths = append(paths, path.String())
	}
	// paths are already sorted by iterator

	values := make([]cid.Cid, len(paths))
	for i, path := range paths {
		values[i], _ = arcs.Get(arcset.Path(path))
	}

	return paths, values
}

// ExtractSortedPathsCells extracts sorted paths and cell-encoded values from an
// arc set. CID-valued arcs are encoded as CID bytes.
func ExtractSortedPathsCells(arcs arcset.ArcSet) ([]string, []Cell) {
	paths, values := ExtractSortedPathsValues(arcs)
	cells := make([]Cell, len(values))
	for i, value := range values {
		cells[i] = CellFromCID(value)
	}
	return paths, cells
}

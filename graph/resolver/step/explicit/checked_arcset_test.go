package explicit_test

import (
	"github.com/dewebprotocol/malt-core/auth/arcset"
	cid "github.com/ipfs/go-cid"
)

func checkedArcSet(arcs map[string]cid.Cid) arcset.ArcSet {
	value, err := arcset.NewArcSet(arcs)
	if err != nil {
		panic(err)
	}
	return value
}

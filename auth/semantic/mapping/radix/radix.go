// Package radix adapts the current Prefix engine to the map convenience API.
package radix

import (
	"github.com/dewebprotocol/malt-core/auth/arcset/materializer"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/input"
	"github.com/dewebprotocol/malt-core/auth/semantic/layoutcompat"
)

type Map struct{ *layoutcompat.Prefix }

func NewMap(scheme commitment.IndexCommitment, store materializer.NodeStore) (*Map, error) {
	p, err := layoutcompat.NewPrefix(scheme, store, nil, input.BytesSHA256)
	if err != nil {
		return nil, err
	}
	return &Map{Prefix: p}, nil
}

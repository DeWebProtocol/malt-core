// Package tree adapts the current Positional engine to the list convenience API.
package tree

import (
	"github.com/dewebprotocol/malt-core/auth/arcset/materializer"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/semantic/layoutcompat"
)

type TreeList struct{ *layoutcompat.Positional }

func NewList(scheme commitment.IndexCommitment, store materializer.NodeStore) (*TreeList, error) {
	p, err := layoutcompat.NewPositional(scheme, store)
	if err != nil {
		return nil, err
	}
	return &TreeList{Positional: p}, nil
}

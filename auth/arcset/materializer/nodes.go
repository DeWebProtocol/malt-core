package materializer

import (
	"context"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
)

// NodeLookup loads one complete immutable vector. Missing state is an error,
// never evidence of an absent application binding. References exclude AA.
type NodeLookup interface {
	GetNode(context.Context, maltcid.NodeRef) ([]commitment.Cell, error)
}
type NodeUpdater interface {
	PutNode(context.Context, maltcid.NodeRef, []commitment.Cell) error
}

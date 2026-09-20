package graph

import (
	"context"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	"github.com/dewebprotocol/malt-core/graph/resolver"
	"github.com/dewebprotocol/malt-core/mutation"
	cid "github.com/ipfs/go-cid"
)

// Resolver is the graph read/proof port.
type Resolver interface {
	// ResolveKey traverses explicit authenticated relations without assuming a
	// payload coordinate. It is the generic graph-data authentication port.
	ResolveKey(ctx context.Context, root cid.Cid, path string) (*resolver.ResolveResult, error)
}

// MutationWriter is the stable graph mutation port. Callers supply an explicit
// base root through mutation.SemanticMutation and receive a result root in the
// write receipt; this interface does not publish heads or arbitrate freshness.
type MutationWriter interface {
	Apply(ctx context.Context, namespace string, mut mutation.SemanticMutation) (mutation.WriteReceipt, error)
}

// StructureCreator bootstraps a semantic structure without claiming that the
// operation is an update from an already authenticated base root.
type StructureCreator interface {
	CreateStructure(ctx context.Context, namespace string, arcs arcset.ArcSet) (cid.Cid, error)
}

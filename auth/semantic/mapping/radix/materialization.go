package radix

import (
	"context"
	"github.com/dewebprotocol/malt-core/auth/arcset"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/semantic/layoutcompat"
	"github.com/dewebprotocol/malt-core/auth/semantic/mapping"
	cid "github.com/ipfs/go-cid"
)

// ValidateMaterialization checks current Prefix vectors against the selected Root.
func ValidateMaterialization(ctx context.Context, scheme commitment.IndexVerifier, root cid.Cid, view mapping.View, witness *arcset.CanonicalArcSet) error {
	return layoutcompat.ValidateMaterialization(ctx, scheme, root, view, witness)
}

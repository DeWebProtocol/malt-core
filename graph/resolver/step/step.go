// Package step defines the Step interface for single-step resolution.
//
// Core runtime wiring ships the explicit MALT arc implementation. Eval-only
// compatibility packages may implement this interface for legacy comparison
// paths, but they are not part of the product resolver boundary.
package step

import (
	"context"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	"github.com/dewebprotocol/malt-core/auth/proof/evidence"
	cid "github.com/ipfs/go-cid"
)

// Step resolves a single step from a root CID.
// It finds the longest matching prefix and returns evidence.
type Step interface {
	// Resolve finds the longest matching prefix and returns evidence.
	// Returns: matchedPath, target, evidence, error
	Resolve(ctx context.Context, root cid.Cid, path arcset.Path) (matchedPath arcset.Path, target cid.Cid, ev evidence.Evidence, err error)

	// Verify verifies the evidence for a resolution step.
	Verify(ctx context.Context, root cid.Cid, path arcset.Path, target cid.Cid, ev evidence.Evidence) (bool, error)
}

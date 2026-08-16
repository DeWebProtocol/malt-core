// Package explicit implements the Step interface for MALT explicit arcs.
// It uses longest-prefix matching in ArcSet materializer and generates cryptographic proof via
// keyed-map semantics.
package explicit

import (
	"context"
	"fmt"
	"strings"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	"github.com/dewebprotocol/malt-core/auth/observation"
	"github.com/dewebprotocol/malt-core/auth/proof/evidence"
	"github.com/dewebprotocol/malt-core/auth/semantic/mapping"
	"github.com/dewebprotocol/malt-core/graph/resolver/step"
	cid "github.com/ipfs/go-cid"
)

// ArcLookup is the minimal explicit-arc lookup capability consumed by the
// resolver. Runtime indexes can implement it without becoming a graph-layer
// dependency.
type ArcLookup interface {
	Get(context.Context, string, cid.Cid, arcset.Path) (cid.Cid, error)
}

// Reserved arc paths for MALT structures
const (
	// PayloadArc is the reserved path that binds a structure root to its payload CID.
	// When resolving a MALT object with an empty path, the upper resolver loop
	// redirects to this arc to materialize the payload.
	PayloadArc arcset.Path = arcset.PayloadPath
)

// Resolver resolves explicit MALT arcs using longest-prefix matching.
type Resolver struct {
	materializer ArcLookup
	semantic     mapping.Semantics
	namespace    string
}

// NewResolver creates a new explicit arc resolver.
func NewResolver(e ArcLookup, semantic mapping.Semantics, namespace string) *Resolver {
	return &Resolver{
		materializer: e,
		semantic:     semantic,
		namespace:    namespace,
	}
}

// Resolve finds the longest matching prefix in the ArcSet materializer and generates proof.
// Returns: matchedPath, target, evidence, error
//
// Example: if ArcSet materializer contains "a/b/c" → key1 and path is "a/b/c/d/e",
// it matches "a/b/c" and returns that path with its target and evidence.
func (r *Resolver) Resolve(ctx context.Context, root cid.Cid, path arcset.Path) (matchedPath arcset.Path, target cid.Cid, ev evidence.Evidence, err error) {
	if !root.Defined() {
		return "", cid.Cid{}, nil, fmt.Errorf("root is not defined")
	}
	if path.IsEmpty() {
		return "", cid.Cid{}, nil, fmt.Errorf("path is empty")
	}

	// Try to find the longest matching prefix
	segments := splitPath(path)

	// Try from longest to shortest
	for i := len(segments); i > 0; i-- {
		candidatePath := arcset.Path(strings.Join(segments[:i], "/"))

		finishLookup := observation.Start(ctx, observation.PhaseArcTable)
		target, err := r.materializer.Get(ctx, r.namespace, root, candidatePath)
		var targetBytes uint64
		if observation.Enabled(ctx) && target.Defined() {
			targetBytes = uint64(target.ByteLen())
		}
		finishLookup(1, 1, targetBytes)
		if err == nil {
			// Found a match, generate proof
			binding, proof, err := r.semantic.Prove(ctx, r.namespace, root, candidatePath)
			if err != nil {
				return "", cid.Cid{}, nil, fmt.Errorf("failed to generate proof: %w", err)
			}

			if !binding.Present || !binding.Value.Equals(target) {
				return "", cid.Cid{}, nil, fmt.Errorf("semantic proof binding mismatch for path: %s", candidatePath.String())
			}
			return candidatePath, target, evidence.NewExplicitEvidence(proof), nil
		}
	}

	return "", cid.Cid{}, nil, fmt.Errorf("no matching arc found for path: %s", path)
}

// Verify verifies a single step's evidence.
func (r *Resolver) Verify(ctx context.Context, root cid.Cid, path arcset.Path, target cid.Cid, ev evidence.Evidence) (bool, error) {
	_ = ctx

	if ev == nil {
		return false, fmt.Errorf("evidence is nil")
	}

	explicitEv, ok := ev.(*evidence.ExplicitEvidence)
	if !ok {
		return false, fmt.Errorf("expected ExplicitEvidence, got %T", ev)
	}

	valid, err := r.semantic.Verify(root, path, mapping.Binding{Value: target, Present: true}, explicitEv.Bytes())
	if err != nil {
		return false, err
	}

	return valid, nil
}

// splitPath splits a path into segments.
func splitPath(path arcset.Path) []string {
	return step.SplitPath(path)
}

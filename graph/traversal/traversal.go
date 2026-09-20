// Package traversal composes typed binding proofs across explicitly selected ArcSet Roots.
package traversal

import (
	"context"
	"errors"
	"fmt"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer"
	"github.com/dewebprotocol/malt-core/auth/engine"
	"github.com/dewebprotocol/malt-core/auth/input"
	cid "github.com/ipfs/go-cid"
)

type Traversal struct {
	Results []engine.Result `json:"results"`
}

// Resolve interprets each explicit step using the AA of the Root reached at
// that step. No string separators or longest-path-prefix policy are involved.
func Resolve(ctx context.Context, e *engine.Engine, root cid.Cid, steps []input.Value, source materializer.NodeLookup) (cid.Cid, Traversal, error) {
	target, proof, err := ResolvePath(ctx, e, root, steps, source)
	if err == nil && !target.Defined() {
		return cid.Undef, Traversal{}, fmt.Errorf("step %d: binding absent", len(proof.Results)-1)
	}
	return target, proof, err
}

// ResolvePath returns an undefined target and a terminal absence proof when a
// selector is absent. Missing materialization and execution failures are errors.
func ResolvePath(ctx context.Context, e *engine.Engine, root cid.Cid, steps []input.Value, source materializer.NodeLookup) (cid.Cid, Traversal, error) {
	return ResolvePathWithRoots(ctx, e, root, steps, func(context.Context, cid.Cid) (materializer.NodeLookup, error) { return source, nil })
}

// RootLookup supplies materialization for the particular ArcSet being queried.
// Recovery and cache policy remain with its caller.
type RootLookup func(context.Context, cid.Cid) (materializer.NodeLookup, error)

// ResolvePathWithRoots lazily obtains nodes for each reached Root. No lookup
// occurs for an unvisited suffix after authenticated absence.
func ResolvePathWithRoots(ctx context.Context, e *engine.Engine, root cid.Cid, steps []input.Value, lookup RootLookup) (cid.Cid, Traversal, error) {
	if lookup == nil {
		return cid.Undef, Traversal{}, errors.New("Root lookup is nil")
	}
	current := root
	out := Traversal{Results: []engine.Result{}}
	if err := e.CheckRoot(root); err != nil {
		return cid.Undef, out, err
	}
	for i, step := range steps {
		source, err := lookup(ctx, current)
		if err != nil {
			return cid.Undef, Traversal{}, fmt.Errorf("step %d: %w", i, err)
		}
		result, err := e.Prove(ctx, current, step, source)
		if err != nil {
			return cid.Undef, Traversal{}, fmt.Errorf("step %d: %w", i, err)
		}
		out.Results = append(out.Results, result)
		if !result.Present {
			return cid.Undef, out, nil
		}
		current = result.Target
	}
	return current, out, nil
}

func Verify(e *engine.Engine, root cid.Cid, steps []input.Value, target cid.Cid, proof Traversal) (bool, error) {
	if !target.Defined() {
		return false, nil
	}
	return VerifyPath(e, root, steps, target, proof)
}

// VerifyPath binds every supplied step to the selected Root. An undefined
// target is valid only for a proven absent selector at the terminal proof step.
func VerifyPath(e *engine.Engine, root cid.Cid, steps []input.Value, target cid.Cid, proof Traversal) (bool, error) {
	if len(proof.Results) > len(steps) {
		return false, nil
	}
	if err := e.CheckRoot(root); err != nil {
		return false, err
	}
	current := root
	for i, result := range proof.Results {
		valid, err := e.Verify(current, steps[i], result)
		if err != nil || !valid {
			return valid, err
		}
		if !result.Present {
			return !target.Defined() && i == len(proof.Results)-1, nil
		}
		current = result.Target
	}
	return target.Defined() && len(steps) == len(proof.Results) && current.Equals(target), nil
}

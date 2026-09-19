// Package authentication is the application-neutral V=0 SDK. Applications
// select inputs, layouts and exact profiles; persistence and trust stay local
// to the caller. Map/List APIs elsewhere are compatibility conveniences.
// All operations use an injected engine; this package imports no concrete VC
// backend. The optional sdk/authentication/verifier package supplies built-ins.
package authentication

import (
	"context"
	"errors"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer"
	"github.com/dewebprotocol/malt-core/auth/engine"
	"github.com/dewebprotocol/malt-core/auth/input"
	"github.com/dewebprotocol/malt-core/protocol"
	cid "github.com/ipfs/go-cid"
)

// RootLookup supplies nodes for one outer Root. Recovery, storage and cache
// policy remain with the caller. It is invoked only for Roots actually queried.
type RootLookup func(context.Context, cid.Cid) (materializer.NodeLookup, error)

func Execute(ctx context.Context, e *engine.Engine, q protocol.AuthenticationRequest, source materializer.NodeLookup) (protocol.AuthenticationResult, error) {
	return ExecuteWithRoots(ctx, e, q, func(context.Context, cid.Cid) (materializer.NodeLookup, error) { return source, nil })
}

// ExecuteWithRoots executes the same protocol against a Root-scoped source.
// This permits lazy recovery of individual ArcSets without expanding the
// application graph or assigning persistence responsibilities to the engine.
func ExecuteWithRoots(ctx context.Context, e *engine.Engine, q protocol.AuthenticationRequest, lookup RootLookup) (protocol.AuthenticationResult, error) {
	if err := q.Validate(); err != nil {
		return protocol.AuthenticationResult{}, err
	}
	if lookup == nil {
		return protocol.AuthenticationResult{}, errors.New("Root lookup is nil")
	}
	root, _ := cid.Decode(q.Root)
	current, _, err := e.Resolve(ctx, root, nil, nil)
	if err != nil {
		return protocol.AuthenticationResult{}, err
	}
	result := protocol.AuthenticationResult{Profile: q.Profile, Traversal: engine.Traversal{Results: []engine.Result{}}}
	for i, step := range q.Steps {
		source, err := lookup(ctx, current)
		if err != nil {
			return protocol.AuthenticationResult{}, err
		}
		target, proof, err := e.ResolvePath(ctx, current, []input.Value{step}, source)
		if err != nil {
			return protocol.AuthenticationResult{}, err
		}
		result.Traversal.Results = append(result.Traversal.Results, proof.Results...)
		if !target.Defined() {
			if q.Profile != protocol.AuthenticationPathProfile {
				return protocol.AuthenticationResult{}, errors.New("traversal binding absent")
			}
			index := uint64(i)
			result.AbsentStep = &index
			return result, nil
		}
		current = target
	}
	result.Resolved = current.String()
	if q.Operation == "resolve" {
		return result, nil
	}
	source, err := lookup(ctx, current)
	if err != nil {
		return protocol.AuthenticationResult{}, err
	}
	switch q.Operation {
	case "binding":
		r, err := e.Prove(ctx, current, *q.Input, source)
		if err != nil {
			return protocol.AuthenticationResult{}, err
		}
		result.Binding = &r
	case "range":
		r, err := e.ProveRange(ctx, current, *q.Start, q.End, source)
		if err != nil {
			return protocol.AuthenticationResult{}, err
		}
		result.Range = &r
	}
	return result, nil
}

// Verify binds the untrusted response to the caller-selected complete Root,
// explicit traversal and primitive query. It never consults server state.
func Verify(e *engine.Engine, q protocol.AuthenticationRequest, result protocol.AuthenticationResult) (bool, error) {
	if err := q.Validate(); err != nil {
		return false, err
	}
	if result.Profile != q.Profile {
		return false, errors.New("unsupported result profile")
	}
	root, _ := cid.Decode(q.Root)
	if result.AbsentStep != nil {
		if q.Profile != protocol.AuthenticationPathProfile || result.Resolved != "" || result.Binding != nil || result.Range != nil ||
			*result.AbsentStep >= uint64(len(q.Steps)) || uint64(len(result.Traversal.Results)) != *result.AbsentStep+1 {
			return false, nil
		}
		return e.VerifyPath(root, q.Steps, cid.Undef, result.Traversal)
	}
	resolved, err := cid.Decode(result.Resolved)
	if err != nil {
		return false, err
	}
	valid, err := e.VerifyTraversal(root, q.Steps, resolved, result.Traversal)
	if err != nil || !valid {
		return valid, err
	}
	switch q.Operation {
	case "resolve":
		return result.Binding == nil && result.Range == nil, nil
	case "binding":
		if result.Binding == nil || result.Range != nil {
			return false, nil
		}
		return e.Verify(resolved, *q.Input, *result.Binding)
	case "range":
		if result.Range == nil || result.Binding != nil {
			return false, nil
		}
		return e.VerifyRange(resolved, *q.Start, q.End, *result.Range)
	}
	return false, errors.New("unknown authentication operation")
}

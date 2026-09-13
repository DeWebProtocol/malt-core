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
	"github.com/dewebprotocol/malt-core/protocol"
	cid "github.com/ipfs/go-cid"
)

func Execute(ctx context.Context, e *engine.Engine, q protocol.AuthenticationRequest, source materializer.NodeLookup) (protocol.AuthenticationResult, error) {
	if err := q.Validate(); err != nil {
		return protocol.AuthenticationResult{}, err
	}
	root, _ := cid.Decode(q.Root)
	resolved, traversal, err := e.Resolve(ctx, root, q.Steps, source)
	if err != nil {
		return protocol.AuthenticationResult{}, err
	}
	result := protocol.AuthenticationResult{Profile: protocol.AuthenticationProfile, Resolved: resolved.String(), Traversal: traversal}
	switch q.Operation {
	case "binding":
		r, err := e.Prove(ctx, resolved, *q.Input, source)
		if err != nil {
			return protocol.AuthenticationResult{}, err
		}
		result.Binding = &r
	case "range":
		r, err := e.ProveRange(ctx, resolved, *q.Start, q.End, source)
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
	if result.Profile != protocol.AuthenticationProfile {
		return false, errors.New("unsupported result profile")
	}
	root, _ := cid.Decode(q.Root)
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

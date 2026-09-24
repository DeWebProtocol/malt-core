// Package object constructs application DAGs from mutable object references.
// Each Object commits one vertex: Immutable returns a content CID, while Map,
// List and tagged structs return a MALT Root. Commit visits children first.
//
// Objects are not safe for concurrent mutation or Commit. Every Commit rebuilds
// the reachable state; a previous CID is never used as a dirty-state shortcut.
// Persistence, publication and trusted-root acceptance belong to the caller.
package object

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	"github.com/dewebprotocol/malt-core/derivation"
	"github.com/dewebprotocol/malt-core/maltcid"
	cid "github.com/ipfs/go-cid"
)

// Object is one vertex in an application DAG. Payload returns cid.Undef when
// the vertex has no payload. Implementations used as children must be non-nil
// pointers. Custom authenticated objects can embed Base and use CommitTagged.
// Recursive implementations must pass the supplied context to their children.
type Object interface {
	Payload() cid.Cid
	Config() CommitConfig
	Commit(context.Context) (cid.Cid, error)
}

// CommitConfig describes how a vertex is committed. Exactly one of
// Authentication or Content is set. Content describes already encoded bytes;
// it is not a vector-commitment backend.
type CommitConfig struct {
	Authentication maltcid.RootDescriptor
	Content        cid.Prefix
}

// MapConfig selects Prefix authentication with SHA256 label derivation.
// The engine must have the selected exact commitment profile installed.
func MapConfig(profile maltcid.ProfileID) CommitConfig {
	return CommitConfig{Authentication: maltcid.RootDescriptor{
		Layout: maltcid.Prefix, DerivationProfile: uint8(derivation.SHA256), Profile: profile,
	}}
}

// ListConfig selects Positional authentication with canonical direct indices.
// Either IPA256 or KZG4096 can be selected independently of the layout.
func ListConfig(profile maltcid.ProfileID) CommitConfig {
	return CommitConfig{Authentication: maltcid.RootDescriptor{
		Layout: maltcid.Positional, DerivationProfile: uint8(derivation.Direct), Profile: profile,
	}}
}

var (
	ErrCycle        = errors.New("object graph contains a cycle")
	ErrNotCommitted = errors.New("object has not been committed")
)

type scopeKey struct{}
type commitScope struct {
	active map[Object]bool
	done   map[Object]cid.Cid
	closed bool
}

func checkObject(o Object) error {
	if o == nil {
		return errors.New("object is nil")
	}
	v := reflect.ValueOf(o)
	if v.Kind() != reflect.Pointer || v.IsNil() {
		return errors.New("object must be a non-nil pointer")
	}
	return nil
}

// withCommit scopes cycle detection and shared-child reuse to this traversal.
// No result from an earlier top-level Commit is used here.
func withCommit(ctx context.Context, self Object, build func(context.Context) (cid.Cid, error)) (cid.Cid, error) {
	if err := ctx.Err(); err != nil {
		return cid.Undef, err
	}
	if err := checkObject(self); err != nil {
		return cid.Undef, err
	}
	s, _ := ctx.Value(scopeKey{}).(*commitScope)
	if s == nil || s.closed {
		s = &commitScope{active: make(map[Object]bool), done: make(map[Object]cid.Cid)}
		ctx = context.WithValue(ctx, scopeKey{}, s)
		defer func() {
			s.closed = true
			clear(s.active)
			clear(s.done)
		}()
	}
	if s.active[self] {
		return cid.Undef, ErrCycle
	}
	if root, ok := s.done[self]; ok {
		return root, nil
	}
	s.active[self] = true
	defer delete(s.active, self)
	root, err := build(ctx)
	if err != nil {
		return cid.Undef, err
	}
	if !root.Defined() {
		return cid.Undef, errors.New("Commit returned an undefined CID")
	}
	s.done[self] = root
	return root, nil
}

func commitChild(ctx context.Context, child Object) (cid.Cid, error) {
	if err := ctx.Err(); err != nil {
		return cid.Undef, err
	}
	if err := checkObject(child); err != nil {
		return cid.Undef, err
	}
	s := ctx.Value(scopeKey{}).(*commitScope)
	if s.active[child] {
		return cid.Undef, ErrCycle
	}
	if root, ok := s.done[child]; ok {
		return root, nil
	}
	root, err := child.Commit(ctx)
	if err != nil {
		return cid.Undef, err
	}
	if !root.Defined() {
		return cid.Undef, fmt.Errorf("%T.Commit returned an undefined CID", child)
	}
	s.done[child] = root
	return root, nil
}

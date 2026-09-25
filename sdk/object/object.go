// Package object constructs application DAGs from mutable object references.
// Each Object commits one vertex: Immutable returns a content CID, while Map,
// List and tagged structs return a MALT Root. Commit visits children first.
//
// Objects are not safe for concurrent mutation or Commit. Every Commit rereads
// reachable references and updates retained ArcSets without dirty tracking.
// New snapshots become visible only after the outermost Commit succeeds.
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

// withCommit scopes cycle detection, shared-child reuse and snapshot staging to
// this traversal. Custom Commit methods should return their helper's result.
func withCommit(ctx context.Context, self Object, build func(context.Context) (*snapshot, error)) (cid.Cid, error) {
	if err := ctx.Err(); err != nil {
		return cid.Undef, err
	}
	if err := checkObject(self); err != nil {
		return cid.Undef, err
	}
	s, _ := ctx.Value(scopeKey{}).(*commitScope)
	top := s == nil || s.closed
	if top {
		s = newScope()
		ctx = context.WithValue(ctx, scopeKey{}, s)
		defer s.close()
	}
	if s.active[self] {
		return cid.Undef, s.fail(ErrCycle)
	}
	if node, ok := s.done[self]; ok {
		return node.root, nil
	}
	s.active[self] = true
	defer delete(s.active, self)
	node, err := build(ctx)
	if err != nil {
		return cid.Undef, s.fail(err)
	}
	if node == nil || !node.root.Defined() {
		return cid.Undef, s.fail(errors.New("Commit returned an undefined CID"))
	}
	if err := ctx.Err(); err != nil {
		return cid.Undef, s.fail(err)
	}
	if s.failed != nil {
		return cid.Undef, s.failed
	}
	s.done[self] = node
	s.byCID[node.root.KeyString()] = node
	if top {
		s.confirm()
	}
	return node.root, nil
}

func commitChild(ctx context.Context, child Object) (*snapshot, error) {
	s := ctx.Value(scopeKey{}).(*commitScope)
	if err := ctx.Err(); err != nil {
		return nil, s.fail(err)
	}
	if err := checkObject(child); err != nil {
		return nil, s.fail(err)
	}
	if s.active[child] {
		return nil, s.fail(ErrCycle)
	}
	if node, ok := s.done[child]; ok {
		return node, nil
	}
	root, err := child.Commit(ctx)
	if err != nil {
		return nil, s.fail(err)
	}
	if !root.Defined() {
		return nil, s.fail(fmt.Errorf("%T.Commit returned an undefined CID", child))
	}
	// A custom Object may delegate to a built-in Commit, or return an external
	// CID. Only cooperating implementations expose bytes and descendants.
	node := s.done[child]
	if node != nil && !node.root.Equals(root) {
		return nil, s.fail(errors.New("custom Commit returned a different CID from its staged snapshot"))
	}
	if node == nil {
		node = s.byCID[root.KeyString()]
	}
	if node == nil {
		node = &snapshot{root: root}
	}
	s.done[child] = node
	return node, nil
}

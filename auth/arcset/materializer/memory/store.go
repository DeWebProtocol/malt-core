// Package memory provides an in-memory ArcSet materializer for SDK examples,
// conformance vectors, and tests. It is not a persistent ArcTable and carries
// no deployment policy.
package memory

import (
	"context"
	"fmt"
	"sync"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	"github.com/dewebprotocol/malt-core/auth/arcset/materializer"
	"github.com/dewebprotocol/malt-core/auth/arcset/materializer/encoded"
	cid "github.com/ipfs/go-cid"
)

type Store struct {
	mu        sync.RWMutex
	branching bool
	scopes    map[string]*scopeState
}

type scopeState struct {
	current    map[arcset.Path]cid.Cid
	nodes      map[arcset.Path]cid.Cid
	nodeRoots  map[string]map[arcset.Path]struct{}
	nodeOwners map[arcset.Path]string
	roots      map[string]map[arcset.Path]cid.Cid
}

// New creates an in-memory materializer. branching controls whether snapshots
// for multiple children of the same root are preserved.
func New(branching bool) *Store {
	return &Store{branching: branching, scopes: map[string]*scopeState{}}
}

func (s *Store) Get(_ context.Context, scope string, root cid.Cid, path arcset.Path) (cid.Cid, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	state := s.scopes[scope]
	if state == nil {
		return cid.Undef, materializer.ErrNotFound
	}
	if root.Defined() {
		snapshot, ok := state.roots[root.KeyString()]
		if !ok {
			return cid.Undef, materializer.ErrNotFound
		}
		if !s.branching {
			snapshot = state.current
		}
		if target, ok := snapshot[path]; ok {
			return target, nil
		}
	}
	if target, ok := state.current[path]; ok {
		return target, nil
	}
	if target, ok := state.nodes[path]; ok {
		return target, nil
	}
	return cid.Undef, materializer.ErrNotFound
}

func (s *Store) BatchGet(ctx context.Context, scope string, root cid.Cid, paths []arcset.Path) (map[arcset.Path]cid.Cid, error) {
	out := make(map[arcset.Path]cid.Cid, len(paths))
	for _, path := range paths {
		target, err := s.Get(ctx, scope, root, path)
		if err == nil {
			out[path] = target
			continue
		}
		if !materializer.IsNotFound(err) {
			return nil, err
		}
	}
	return out, nil
}

func (s *Store) Update(_ context.Context, scope string, newRoot, oldRoot cid.Cid, values arcset.ArcSet) error {
	delta, err := arcset.ToPathMap(values)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.ensureScope(scope)
	if !newRoot.Defined() {
		apply(state.current, delta)
		return nil
	}

	base := map[arcset.Path]cid.Cid{}
	if !s.branching {
		base = clone(state.current)
	}
	if oldRoot.Defined() {
		previous, ok := state.roots[oldRoot.KeyString()]
		if !ok {
			if s.branching {
				return materializer.ErrNotFound
			}
			previous = state.current
		}
		if s.branching {
			base = clone(previous)
			for path, target := range state.current {
				base[path] = target
			}
		}
	} else if s.branching {
		base = clone(state.current)
	}
	apply(base, delta)
	if !s.branching {
		state.roots = map[string]map[arcset.Path]cid.Cid{}
		state.current = clone(base)
	}
	state.roots[newRoot.KeyString()] = base
	return nil
}

// UpdateNode installs unversioned node-cache entries and records their owning
// semantic node root for reachability-based reclamation.
func (s *Store) UpdateNode(_ context.Context, scope string, root cid.Cid, values arcset.ArcSet) error {
	if !root.Defined() {
		return materializer.ErrNotFound
	}
	delta, err := arcset.ToPathMap(values)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.ensureScope(scope)
	rootKey := root.KeyString()
	paths := state.nodeRoots[rootKey]
	if paths == nil {
		paths = make(map[arcset.Path]struct{}, len(delta))
	}
	for path, target := range delta {
		if !target.Defined() {
			continue
		}
		if owner, owned := state.nodeOwners[path]; owned && owner != rootKey {
			return fmt.Errorf("node materializer path %q is already owned by another root", path)
		}
	}
	state.nodeRoots[rootKey] = paths
	for path, target := range delta {
		if target.Defined() {
			state.nodes[path] = target
			paths[path] = struct{}{}
			state.nodeOwners[path] = rootKey
		} else {
			if owner, owned := state.nodeOwners[path]; !owned || owner != rootKey {
				continue
			}
			delete(state.nodes, path)
			delete(paths, path)
			delete(state.nodeOwners, path)
		}
	}
	if len(paths) == 0 {
		delete(state.nodeRoots, rootKey)
	}
	return nil
}

func (s *Store) Snapshot(_ context.Context, scope string, root cid.Cid) (arcset.ArcSet, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	state := s.scopes[scope]
	if state == nil {
		return nil, materializer.ErrNotFound
	}
	values := state.current
	if root.Defined() {
		var ok bool
		values, ok = state.roots[root.KeyString()]
		if !ok {
			return nil, materializer.ErrNotFound
		}
		if !s.branching {
			values = state.current
		}
	}
	return arcset.NewArcSetFromPaths(clone(values))
}

func (s *Store) Iterate(ctx context.Context, scope string, root cid.Cid) arcset.Iterator {
	view, err := s.Snapshot(ctx, scope, root)
	if err != nil {
		return &errorIterator{err: err}
	}
	return view.Iterate()
}

func (s *Store) Close() error { return nil }

// RetainRoots removes versioned snapshots that are not reachable from the
// supplied roots. Reachability follows CID targets within each scope. Scopes
// absent from retain are removed entirely. The helper is intentionally
// specific to this in-memory implementation; long-lived speculative SDK
// sessions use it to release abandoned branches without adding lifecycle
// policy to the portable materializer interfaces.
func (s *Store) RetainRoots(retain map[string][]cid.Cid) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	removed := 0
	for scope, state := range s.scopes {
		roots, keepScope := retain[scope]
		if !keepScope {
			removed += len(state.roots)
			delete(s.scopes, scope)
			continue
		}

		reachable := make(map[string]struct{}, len(roots))
		pending := make([]string, 0, len(roots))
		for _, root := range roots {
			if root.Defined() {
				pending = append(pending, root.KeyString())
				if node, err := encoded.RootIdentity(root); err == nil {
					pending = append(pending, node.KeyString())
				}
			}
		}
		for len(pending) > 0 {
			last := len(pending) - 1
			key := pending[last]
			pending = pending[:last]
			if _, seen := reachable[key]; seen {
				continue
			}
			if root, err := cid.Cast([]byte(key)); err == nil {
				if node, err := encoded.RootIdentity(root); err == nil {
					pending = append(pending, node.KeyString())
				}
			}
			snapshot, exists := state.roots[key]
			nodePaths, nodeExists := state.nodeRoots[key]
			if !exists && !nodeExists {
				continue
			}
			reachable[key] = struct{}{}

			for _, target := range snapshot {
				if target.Defined() {
					if node, err := encoded.RootIdentity(target); err == nil {
						pending = append(pending, node.KeyString())
					}
					targetKey := target.KeyString()
					if _, rootExists := state.roots[targetKey]; rootExists {
						pending = append(pending, targetKey)
					} else if _, nodeRootExists := state.nodeRoots[targetKey]; nodeRootExists {
						pending = append(pending, targetKey)
					}
				}
			}
			for path := range nodePaths {
				target := state.nodes[path]
				for _, reference := range encoded.References(target) {
					pending = append(pending, reference.KeyString())
				}
				if target.Defined() {
					if node, err := encoded.RootIdentity(target); err == nil {
						pending = append(pending, node.KeyString())
					}
					targetKey := target.KeyString()
					if _, rootExists := state.roots[targetKey]; rootExists {
						pending = append(pending, targetKey)
					} else if _, nodeRootExists := state.nodeRoots[targetKey]; nodeRootExists {
						pending = append(pending, targetKey)
					}
				}
			}
		}
		for key := range state.roots {
			if _, keep := reachable[key]; !keep {
				delete(state.roots, key)
				removed++
			}
		}
		for key, paths := range state.nodeRoots {
			if _, keep := reachable[key]; keep {
				continue
			}
			for path := range paths {
				delete(state.nodes, path)
				delete(state.nodeOwners, path)
			}
			delete(state.nodeRoots, key)
			removed++
		}
	}
	return removed
}

// RootCount reports the number of retained versioned snapshots. It is useful
// for bounded-lifecycle tests and diagnostics of this in-memory store.
func (s *Store) RootCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	count := 0
	for _, state := range s.scopes {
		count += len(state.roots)
	}
	return count
}

// EntryCount reports all retained current-cache entries plus versioned
// snapshot entries. It is intended for bounded-lifecycle regression tests.
func (s *Store) EntryCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	count := 0
	for _, state := range s.scopes {
		count += len(state.current) + len(state.nodes)
		for _, snapshot := range state.roots {
			count += len(snapshot)
		}
	}
	return count
}

func (s *Store) ensureScope(scope string) *scopeState {
	state := s.scopes[scope]
	if state == nil {
		state = &scopeState{
			current:    map[arcset.Path]cid.Cid{},
			nodes:      map[arcset.Path]cid.Cid{},
			nodeRoots:  map[string]map[arcset.Path]struct{}{},
			nodeOwners: map[arcset.Path]string{},
			roots:      map[string]map[arcset.Path]cid.Cid{},
		}
		s.scopes[scope] = state
	}
	return state
}

func apply(target, delta map[arcset.Path]cid.Cid) {
	for path, value := range delta {
		if value.Defined() {
			target[path] = value
		} else {
			delete(target, path)
		}
	}
}

func clone(values map[arcset.Path]cid.Cid) map[arcset.Path]cid.Cid {
	out := make(map[arcset.Path]cid.Cid, len(values))
	for path, value := range values {
		out[path] = value
	}
	return out
}

type errorIterator struct{ err error }

func (i *errorIterator) Next() (arcset.Path, cid.Cid, bool) { return "", cid.Undef, false }
func (i *errorIterator) Err() error                         { return i.err }
func (i *errorIterator) Close()                             {}

var (
	_ materializer.Lookup      = (*Store)(nil)
	_ materializer.Updater     = (*Store)(nil)
	_ materializer.Snapshotter = (*Store)(nil)
	_ materializer.Iterator    = (*Store)(nil)
)

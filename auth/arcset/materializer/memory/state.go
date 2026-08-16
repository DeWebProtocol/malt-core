package memory

import (
	"fmt"
	"sort"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	cid "github.com/ipfs/go-cid"
)

// State is a detached representation of one in-memory materializer. It lets a
// caller checkpoint ephemeral SDK execution state without assigning durable
// storage or trust policy to MALT Core.
type State struct {
	Branching bool         `json:"branching"`
	Scopes    []ScopeState `json:"scopes"`
}

type ScopeState struct {
	Scope     string          `json:"scope"`
	Current   []Entry         `json:"current"`
	Nodes     []Entry         `json:"nodes"`
	NodeRoots []NodeRootState `json:"node_roots"`
	Roots     []RootState     `json:"roots"`
}

type Entry struct {
	Path   arcset.Path `json:"path"`
	Target cid.Cid     `json:"target"`
}

type NodeRootState struct {
	Root  cid.Cid       `json:"root"`
	Paths []arcset.Path `json:"paths"`
}

type RootState struct {
	Root    cid.Cid `json:"root"`
	Entries []Entry `json:"entries"`
}

// ExportState returns a deterministic detached copy of the materializer.
func (s *Store) ExportState() (State, error) {
	if s == nil {
		return State{}, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := State{Branching: s.branching, Scopes: make([]ScopeState, 0, len(s.scopes))}
	scopes := make([]string, 0, len(s.scopes))
	for scope := range s.scopes {
		scopes = append(scopes, scope)
	}
	sort.Strings(scopes)
	for _, scope := range scopes {
		state := s.scopes[scope]
		wire := ScopeState{
			Scope:   scope,
			Current: sortedEntries(state.current),
			Nodes:   sortedEntries(state.nodes),
		}
		nodeRoots := make([]string, 0, len(state.nodeRoots))
		for root := range state.nodeRoots {
			nodeRoots = append(nodeRoots, root)
		}
		sort.Strings(nodeRoots)
		for _, rootKey := range nodeRoots {
			root, err := cid.Cast([]byte(rootKey))
			if err != nil {
				return State{}, fmt.Errorf("decode materializer node root: %w", err)
			}
			paths := make([]arcset.Path, 0, len(state.nodeRoots[rootKey]))
			for path := range state.nodeRoots[rootKey] {
				paths = append(paths, path)
			}
			sort.Slice(paths, func(i, j int) bool { return paths[i].String() < paths[j].String() })
			wire.NodeRoots = append(wire.NodeRoots, NodeRootState{Root: root, Paths: paths})
		}
		roots := make([]string, 0, len(state.roots))
		for root := range state.roots {
			roots = append(roots, root)
		}
		sort.Strings(roots)
		for _, rootKey := range roots {
			root, err := cid.Cast([]byte(rootKey))
			if err != nil {
				return State{}, fmt.Errorf("decode materializer root: %w", err)
			}
			wire.Roots = append(wire.Roots, RootState{Root: root, Entries: sortedEntries(state.roots[rootKey])})
		}
		out.Scopes = append(out.Scopes, wire)
	}
	return out, nil
}

// NewFromState validates and restores a detached in-memory state.
func NewFromState(input State) (*Store, error) {
	store := New(input.Branching)
	seenScopes := make(map[string]struct{}, len(input.Scopes))
	for _, scope := range input.Scopes {
		if _, duplicate := seenScopes[scope.Scope]; duplicate {
			return nil, fmt.Errorf("duplicate materializer scope %q", scope.Scope)
		}
		seenScopes[scope.Scope] = struct{}{}
		state := store.ensureScope(scope.Scope)
		var err error
		if state.current, err = entriesMap(scope.Current); err != nil {
			return nil, fmt.Errorf("scope %q current state: %w", scope.Scope, err)
		}
		if state.nodes, err = entriesMap(scope.Nodes); err != nil {
			return nil, fmt.Errorf("scope %q node state: %w", scope.Scope, err)
		}
		for _, root := range scope.Roots {
			if !root.Root.Defined() {
				return nil, fmt.Errorf("scope %q contains an undefined root", scope.Scope)
			}
			key := root.Root.KeyString()
			if _, duplicate := state.roots[key]; duplicate {
				return nil, fmt.Errorf("scope %q contains duplicate root %s", scope.Scope, root.Root)
			}
			entries, err := entriesMap(root.Entries)
			if err != nil {
				return nil, fmt.Errorf("scope %q root %s: %w", scope.Scope, root.Root, err)
			}
			state.roots[key] = entries
		}
		for _, root := range scope.NodeRoots {
			if !root.Root.Defined() {
				return nil, fmt.Errorf("scope %q contains an undefined node root", scope.Scope)
			}
			key := root.Root.KeyString()
			if _, duplicate := state.nodeRoots[key]; duplicate {
				return nil, fmt.Errorf("scope %q contains duplicate node root %s", scope.Scope, root.Root)
			}
			paths := make(map[arcset.Path]struct{}, len(root.Paths))
			for _, path := range root.Paths {
				canonical, err := arcset.NewPath(path.String())
				if err != nil || canonical != path {
					return nil, fmt.Errorf("scope %q node root %s contains invalid path %q", scope.Scope, root.Root, path)
				}
				if _, exists := state.nodes[path]; !exists {
					return nil, fmt.Errorf("scope %q node root %s references missing path %q", scope.Scope, root.Root, path)
				}
				if _, duplicate := state.nodeOwners[path]; duplicate {
					return nil, fmt.Errorf("scope %q node path %q has multiple owners", scope.Scope, path)
				}
				state.nodeOwners[path] = key
				paths[path] = struct{}{}
			}
			state.nodeRoots[key] = paths
		}
		if len(state.nodeOwners) != len(state.nodes) {
			return nil, fmt.Errorf("scope %q contains unowned node paths", scope.Scope)
		}
	}
	return store, nil
}

func sortedEntries(values map[arcset.Path]cid.Cid) []Entry {
	paths := make([]arcset.Path, 0, len(values))
	for path := range values {
		paths = append(paths, path)
	}
	sort.Slice(paths, func(i, j int) bool { return paths[i].String() < paths[j].String() })
	out := make([]Entry, 0, len(paths))
	for _, path := range paths {
		out = append(out, Entry{Path: path, Target: values[path]})
	}
	return out
}

func entriesMap(entries []Entry) (map[arcset.Path]cid.Cid, error) {
	out := make(map[arcset.Path]cid.Cid, len(entries))
	for _, entry := range entries {
		path, err := arcset.NewPath(entry.Path.String())
		if err != nil || path != entry.Path {
			return nil, fmt.Errorf("invalid materializer path %q", entry.Path)
		}
		if !entry.Target.Defined() {
			return nil, fmt.Errorf("materializer path %q has an undefined target", entry.Path)
		}
		if existing, duplicate := out[path]; duplicate {
			if !existing.Equals(entry.Target) {
				return nil, fmt.Errorf("materializer path %q has conflicting targets", entry.Path)
			}
			return nil, fmt.Errorf("duplicate materializer path %q", entry.Path)
		}
		out[path] = entry.Target
	}
	return out, nil
}

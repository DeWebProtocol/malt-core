package arcset

import (
	"fmt"
	"slices"

	cid "github.com/ipfs/go-cid"
)

// Set is an immutable in-memory ArcSet implementation.
// It is safe for concurrent read access.
// Do not modify the underlying map after creation.
type Set struct {
	arcs map[Path]cid.Cid
}

// NewSet creates an empty in-memory arc set.
func NewSet() *Set {
	return &Set{arcs: make(map[Path]cid.Cid)}
}

// NewArcSet creates an immutable arc set from path strings.
// Input paths are canonicalized before insertion. Empty canonical paths and
// conflicting duplicate canonical paths are reported as errors.
func NewArcSet(arcs map[string]cid.Cid) (ArcSet, error) {
	out := make(map[Path]cid.Cid, len(arcs))
	for rawPath, target := range arcs {
		path, err := NewPath(rawPath)
		if err != nil {
			return nil, err
		}
		if existing, ok := out[path]; ok && !cidEqual(existing, target) {
			return nil, &PathError{Path: rawPath, Err: fmt.Errorf("%w %q", ErrDuplicatePath, path.String())}
		}
		out[path] = target
	}
	return &Set{arcs: out}, nil
}

// NewArcSetFromPaths creates an immutable arc set from canonical paths.
func NewArcSetFromPaths(arcs map[Path]cid.Cid) (ArcSet, error) {
	out := make(map[Path]cid.Cid, len(arcs))
	for path, target := range arcs {
		if path.IsEmpty() {
			return nil, &PathError{Err: ErrEmptyPath}
		}
		out[path] = target
	}
	return &Set{arcs: out}, nil
}

// Get retrieves the target CID for a path.
func (m *Set) Get(path Path) (cid.Cid, bool) {
	c, ok := m.arcs[path]
	return c, ok
}

// Iterate returns an iterator over all arcs.
func (m *Set) Iterate() Iterator {
	return &memoryIterator{arcs: m.arcs, keys: getSortedKeys(m.arcs)}
}

// Len returns the number of arcs.
func (m *Set) Len() int {
	return len(m.arcs)
}

type memoryIterator struct {
	arcs  map[Path]cid.Cid
	keys  []Path
	index int
}

func getSortedKeys(m map[Path]cid.Cid) []Path {
	keys := make([]Path, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func (it *memoryIterator) Next() (Path, cid.Cid, bool) {
	if it.index >= len(it.keys) {
		return "", cid.Cid{}, false
	}
	key := it.keys[it.index]
	it.index++
	return key, it.arcs[key], true
}

func (it *memoryIterator) Err() error { return nil }

func (it *memoryIterator) Close() {}

var _ ArcSet = (*Set)(nil)

// ToPathMap clones an arc set into its canonical path map form.
func ToPathMap(arcs ArcSet) (map[Path]cid.Cid, error) {
	if arcs == nil {
		return nil, fmt.Errorf("arc set is nil")
	}

	out := make(map[Path]cid.Cid, arcs.Len())
	iter := arcs.Iterate()
	defer iter.Close()
	for {
		path, target, ok := iter.Next()
		if !ok {
			break
		}
		if path.IsEmpty() {
			return nil, &PathError{Err: ErrEmptyPath}
		}
		if existing, ok := out[path]; ok && !cidEqual(existing, target) {
			return nil, &PathError{Path: path.String(), Err: fmt.Errorf("%w %q", ErrDuplicatePath, path.String())}
		}
		out[path] = target
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func cidEqual(a, b cid.Cid) bool {
	if !a.Defined() && !b.Defined() {
		return true
	}
	return a.Equals(b)
}

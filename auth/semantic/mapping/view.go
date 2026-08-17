package mapping

import (
	"slices"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	cid "github.com/ipfs/go-cid"
)

// SetView is an immutable in-memory keyed view used by mapping semantics and tests.
type SetView struct {
	entries map[arcset.Path]cid.Cid
}

// NewViewFrom creates an immutable keyed view from raw path strings.
func NewViewFrom(entries map[string]cid.Cid) *SetView {
	out := make(map[arcset.Path]cid.Cid, len(entries))
	for path, target := range entries {
		out[arcset.CanonicalizePath(path)] = target
	}
	return &SetView{entries: out}
}

// NewViewFromArcSet creates an immutable keyed view from a canonical arc set.
func NewViewFromArcSet(arcs arcset.ArcSet) (*SetView, error) {
	entries, err := arcset.ToPathMap(arcs)
	if err != nil {
		return nil, err
	}
	return NewViewFromPaths(entries), nil
}

// NewViewFromPaths creates an immutable keyed view from canonical paths.
func NewViewFromPaths(entries map[arcset.Path]cid.Cid) *SetView {
	out := make(map[arcset.Path]cid.Cid, len(entries))
	for path, target := range entries {
		out[path] = target
	}
	return &SetView{entries: out}
}

// Len returns the number of bindings in the view.
func (v *SetView) Len() int {
	return len(v.entries)
}

// Get returns the value bound to key.
func (v *SetView) Get(key arcset.Path) (cid.Cid, bool) {
	target, ok := v.entries[key]
	return target, ok
}

// Iterate returns an iterator over all bindings in canonical order.
func (v *SetView) Iterate() Iterator {
	keys := make([]arcset.Path, 0, len(v.entries))
	for key := range v.entries {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return &setIterator{
		entries: v.entries,
		keys:    keys,
	}
}

type setIterator struct {
	entries map[arcset.Path]cid.Cid
	keys    []arcset.Path
	index   int
}

func (it *setIterator) Next() (arcset.Path, cid.Cid, bool) {
	if it.index >= len(it.keys) {
		return "", cid.Undef, false
	}
	key := it.keys[it.index]
	it.index++
	return key, it.entries[key], true
}

func (it *setIterator) Err() error {
	return nil
}

var _ View = (*SetView)(nil)

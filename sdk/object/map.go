package object

import (
	"context"
	"errors"

	"github.com/dewebprotocol/malt-core/engine"
	cid "github.com/ipfs/go-cid"
)

// Map is a Prefix Object whose byte labels point to other Objects. Labels are
// opaque, including empty and binary labels; no path splitting is performed.
type Map struct {
	*Base
	entries map[string]Object
}

func NewMap(e *engine.Engine, config CommitConfig) (*Map, error) {
	b, err := NewBase(e, config)
	if err != nil {
		return nil, err
	}
	return &Map{Base: b, entries: make(map[string]Object)}, nil
}

// Set adds or replaces a reference, copying the label but retaining the child
// reference. Mutating the child will be observed by the next recursive Commit.
func (m *Map) Set(label []byte, target Object) error {
	if m == nil || m.Base == nil || m.entries == nil {
		return errors.New("Map is not initialized")
	}
	if err := checkLabel(m.Config(), label); err != nil {
		return err
	}
	if err := checkObject(target); err != nil {
		return err
	}
	m.entries[string(label)] = target
	return nil
}

func (m *Map) Get(label []byte) (Object, bool) {
	if label == nil {
		return nil, false
	}
	v, ok := m.entries[string(label)]
	return v, ok
}

func (m *Map) Delete(label []byte) bool {
	if _, ok := m.Get(label); !ok {
		return false
	}
	delete(m.entries, string(label))
	return true
}

// Len counts user references, excluding the optional payload binding.
func (m *Map) Len() int { return len(m.entries) }

func (m *Map) Commit(ctx context.Context) (cid.Cid, error) {
	return withCommit(ctx, m, func(ctx context.Context) (*snapshot, error) {
		refs := make([]reference, 0, len(m.entries))
		for label, target := range m.entries {
			refs = append(refs, reference{label: []byte(label), target: target})
		}
		return m.Base.commitReferences(ctx, m, refs)
	})
}

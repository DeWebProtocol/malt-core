package object

import (
	"context"
	"fmt"
	"math"
	"slices"
	"sort"

	"github.com/dewebprotocol/malt-core/auth/coordinate"
	"github.com/dewebprotocol/malt-core/engine"
	"github.com/dewebprotocol/malt-core/maltcid"
	"github.com/dewebprotocol/malt-core/sdk/authentication"
	cid "github.com/ipfs/go-cid"
)

// List binds objects at zero-based integer indices. Gaps occupy no storage.
// Its optional application content reference is authenticated in root metadata.
type List struct {
	authenticated
	items   []listItem // sorted by index
	payload cid.Cid
}

type listItem struct {
	index  int
	object Object
}

func NewList(e *engine.Engine, config CommitConfig) (*List, error) {
	a, err := newAuthenticated(e, config, maltcid.List)
	if err != nil {
		return nil, err
	}
	return &List{authenticated: a}, nil
}

func (l *List) Config() CommitConfig { return l.config }
func (l *List) Payload() cid.Cid     { return l.payload }

// SetPayload binds already encoded application content without consuming an index.
// Undef clears the payload. Truncating items does not clear it.
func (l *List) SetPayload(payload cid.Cid) { l.payload = payload }

// CID is the last successful Commit result, not a dirty-state check.
func (l *List) CID() cid.Cid { return l.cid() }

// Writer returns this List's last successful immutable authentication state.
func (l *List) Writer() (*authentication.Writer, error) { return l.retained() }

// Delta compares the exact graphs used by the last two successful Commits.
func (l *List) Delta(ctx context.Context) (Delta, error) { return l.delta(ctx) }

// Len is one past the highest bound index, or zero for an empty List.
func (l *List) Len() int {
	if len(l.items) == 0 {
		return 0
	}
	return l.items[len(l.items)-1].index + 1
}

func (l *List) position(index int) int {
	return sort.Search(len(l.items), func(i int) bool { return l.items[i].index >= index })
}

// Get returns nil for an empty cell inside the List.
func (l *List) Get(index int) (Object, error) {
	if index < 0 || index >= l.Len() {
		return nil, fmt.Errorf("list index %d is out of range", index)
	}
	i := l.position(index)
	if l.items[i].index != index {
		return nil, nil
	}
	return l.items[i].object, nil
}

// Set fills or replaces a cell within the existing extent.
func (l *List) Set(index int, target Object) error {
	if index < 0 || index >= l.Len() {
		return fmt.Errorf("list index %d is out of range", index)
	}
	return l.Bind(index, target)
}

// Bind places a reference at index, extending the List across empty cells as needed.
func (l *List) Bind(index int, target Object) error {
	if index < 0 || index == math.MaxInt {
		return fmt.Errorf("list index %d is out of range", index)
	}
	if err := checkObject(target); err != nil {
		return err
	}
	i := l.position(index)
	if i == len(l.items) || l.items[i].index != index {
		l.items = slices.Insert(l.items, i, listItem{index: index, object: target})
	} else {
		l.items[i].object = target
	}
	return nil
}

// Append validates all references before changing the List.
func (l *List) Append(targets ...Object) error {
	first := l.Len()
	if len(targets) > math.MaxInt-first {
		return fmt.Errorf("List length overflows int")
	}
	for i, target := range targets {
		if err := checkObject(target); err != nil {
			return fmt.Errorf("item %d: %w", i, err)
		}
	}
	for i, target := range targets {
		l.items = append(l.items, listItem{index: first + i, object: target})
	}
	return nil
}

// Clear removes a binding while preserving all other indices.
func (l *List) Clear(index int) error {
	if index < 0 || index >= l.Len() {
		return fmt.Errorf("list index %d is out of range", index)
	}
	i := l.position(index)
	if l.items[i].index == index {
		l.items = slices.Delete(l.items, i, i+1)
	}
	return nil
}

// Remove shifts every subsequent index down by one, including across gaps.
func (l *List) Remove(index int) error {
	if err := l.Clear(index); err != nil {
		return err
	}
	for i := l.position(index); i < len(l.items); i++ {
		l.items[i].index--
	}
	return nil
}

func (l *List) Commit(ctx context.Context) (cid.Cid, error) {
	return withCommit(ctx, l, func(ctx context.Context) (*snapshot, error) {
		if err := checkConfig(l.engine, l.Config(), maltcid.List); err != nil {
			return nil, err
		}
		entries := make([]engine.Entry, len(l.items))
		children := make([]*snapshot, len(l.items))
		for i, child := range l.items {
			target, err := commitChild(ctx, child.object)
			if err != nil {
				return nil, fmt.Errorf("index %d: %w", child.index, err)
			}
			entries[i] = engine.Entry{Label: coordinate.EncodeIndex(uint64(child.index)), Target: target.root}
			children[i] = target
		}
		if l.payload.Defined() {
			children = append(children, &snapshot{root: l.payload})
		}
		return l.authenticated.commit(ctx, l, l.Config(), entries, children)
	})
}

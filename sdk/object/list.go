package object

import (
	"context"
	"fmt"

	"github.com/dewebprotocol/malt-core/auth/coordinate"
	"github.com/dewebprotocol/malt-core/engine"
	"github.com/dewebprotocol/malt-core/maltcid"
	"github.com/dewebprotocol/malt-core/sdk/authentication"
	cid "github.com/ipfs/go-cid"
)

// List is a Positional Object with dense, zero-based references. Removing an
// item shifts its successors down by one; replacing an item preserves its index.
// This initial container has no independent payload; Payload returns cid.Undef.
type List struct {
	authenticated
	items []Object
}

func NewList(e *engine.Engine, config CommitConfig) (*List, error) {
	a, err := newAuthenticated(e, config, maltcid.Positional)
	if err != nil {
		return nil, err
	}
	return &List{authenticated: a}, nil
}

func (l *List) Config() CommitConfig { return l.config }
func (l *List) Payload() cid.Cid     { return cid.Undef }

// CID is the last successful Commit result, not a dirty-state check.
func (l *List) CID() cid.Cid { return l.cid() }

// Writer returns this List's last successful immutable authentication state.
func (l *List) Writer() (*authentication.Writer, error) { return l.retained() }

// Delta compares the exact graphs used by the last two successful Commits.
func (l *List) Delta(ctx context.Context) (Delta, error) { return l.delta(ctx) }

func (l *List) Len() int { return len(l.items) }

func (l *List) Get(index int) (Object, error) {
	if index < 0 || index >= len(l.items) {
		return nil, fmt.Errorf("list index %d is out of range", index)
	}
	return l.items[index], nil
}

func (l *List) Set(index int, target Object) error {
	if _, err := l.Get(index); err != nil {
		return err
	}
	if err := checkObject(target); err != nil {
		return err
	}
	l.items[index] = target
	return nil
}

// Append validates all references before changing the List.
func (l *List) Append(targets ...Object) error {
	for i, target := range targets {
		if err := checkObject(target); err != nil {
			return fmt.Errorf("item %d: %w", i, err)
		}
	}
	l.items = append(l.items, targets...)
	return nil
}

func (l *List) Remove(index int) error {
	if _, err := l.Get(index); err != nil {
		return err
	}
	copy(l.items[index:], l.items[index+1:])
	l.items[len(l.items)-1] = nil
	l.items = l.items[:len(l.items)-1]
	return nil
}

func (l *List) Commit(ctx context.Context) (cid.Cid, error) {
	return withCommit(ctx, l, func(ctx context.Context) (*snapshot, error) {
		if err := checkConfig(l.engine, l.Config(), maltcid.Positional); err != nil {
			return nil, err
		}
		entries := make([]engine.Entry, len(l.items))
		children := make([]*snapshot, len(l.items))
		for i, child := range l.items {
			target, err := commitChild(ctx, child)
			if err != nil {
				return nil, fmt.Errorf("index %d: %w", i, err)
			}
			entries[i] = engine.Entry{Label: coordinate.EncodeIndex(uint64(i)), Target: target.root}
			children[i] = target
		}
		return l.authenticated.commit(ctx, l, l.Config(), entries, children)
	})
}

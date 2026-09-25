package object

import (
	"context"
	"errors"

	"github.com/dewebprotocol/malt-core/sdk/authentication"
	cid "github.com/ipfs/go-cid"
)

// A marker identifies a local vertex across versions without retaining the
// mutable Object itself. Nonzero size keeps distinct markers distinct.
type vertexID struct{ marker byte }

// snapshot contains immutable version data only. Child links retain the exact
// versions used by this parent, even after a child is committed independently.
// It never points to a history, mutable Object, or a preceding snapshot.
type snapshot struct {
	id       *vertexID
	root     cid.Cid
	config   CommitConfig
	writer   *authentication.Writer
	children []*snapshot
	block    *Block
}

type history struct {
	id     *vertexID
	before *snapshot
	after  *snapshot
}

func newHistory() history { return history{id: &vertexID{}} }

func (h *history) cid() cid.Cid {
	if h.after == nil {
		return cid.Undef
	}
	return h.after.root
}

func (h *history) delta(ctx context.Context) (Delta, error) {
	if h.after == nil {
		return Delta{}, ErrNotCommitted
	}
	return diffSnapshots(ctx, h.before, h.after)
}

type scopeKey struct{}

type stagedSnapshot struct {
	owner Object
	value *snapshot
}

type commitScope struct {
	active map[Object]bool
	done   map[Object]*snapshot
	byCID  map[string]*snapshot
	staged map[*history]stagedSnapshot
	ids    map[*vertexID]*history
	failed error
	closed bool
}

func newScope() *commitScope {
	return &commitScope{
		active: make(map[Object]bool), done: make(map[Object]*snapshot),
		byCID: make(map[string]*snapshot), staged: make(map[*history]stagedSnapshot),
		ids: make(map[*vertexID]*history),
	}
}

func (h *history) stage(ctx context.Context, self Object, next *snapshot) (*snapshot, error) {
	s := ctx.Value(scopeKey{}).(*commitScope)
	if h.id == nil {
		return nil, errors.New("Object is not initialized")
	}
	if old, ok := s.staged[h]; ok && old.owner != self {
		return nil, errors.New("Objects cannot share a Base")
	}
	if old := s.ids[h.id]; old != nil && old != h {
		return nil, errors.New("Object state was copied; retain Object pointers instead")
	}
	next.id = h.id
	s.ids[h.id] = h
	s.staged[h] = stagedSnapshot{owner: self, value: next}
	return next, nil
}

func (s *commitScope) fail(err error) error {
	if s.failed == nil {
		s.failed = err
	}
	return err
}

// confirm contains no fallible work or application callbacks. All snapshots
// advance together after computation and the final cancellation check succeed.
func (s *commitScope) confirm() {
	for h, staged := range s.staged {
		h.before, h.after = h.after, staged.value
	}
}

func (s *commitScope) close() {
	s.closed = true
	clear(s.active)
	clear(s.done)
	clear(s.byCID)
	clear(s.staged)
	clear(s.ids)
}

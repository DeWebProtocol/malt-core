package authentication

import (
	"context"
	"errors"
	"math"
	"strconv"
	"sync"

	"github.com/dewebprotocol/malt-core/engine"
	"github.com/dewebprotocol/malt-core/protocol"
	cid "github.com/ipfs/go-cid"
)

// SessionLimits bound retained candidates and their conservative state charge.
// Shared subtrees are charged to every candidate; this is intentionally not an
// allocator-exact metric. Zero fields select the defaults.
type SessionLimits struct {
	MaxCandidates int
	MaxStateBytes uint64
}
type Handle struct {
	ID   string
	Root cid.Cid
}

// Session is a local, bounded set of immutable writer branches. Handles never
// imply publication or trusted-root acceptance. Discard releases a branch;
// Clear releases all branches without ever reusing a previously issued handle.
type Session struct {
	mu      sync.Mutex
	engine  *engine.Engine
	limits  SessionLimits
	writers map[string]*Writer
	charge  uint64
	next    uint64
}

func NewSession(e *engine.Engine, limits SessionLimits) (*Session, error) {
	if e == nil || e.Tree == nil {
		return nil, errors.New("authentication engine is required")
	}
	if limits.MaxCandidates == 0 {
		limits.MaxCandidates = 64
	}
	if limits.MaxStateBytes == 0 {
		limits.MaxStateBytes = 64 << 20
	}
	if limits.MaxCandidates < 1 {
		return nil, errors.New("candidate limit must be positive")
	}
	return &Session{engine: e, limits: limits, writers: make(map[string]*Writer)}, nil
}
func (s *Session) capacity() error {
	if len(s.writers) >= s.limits.MaxCandidates || s.next == math.MaxUint64 {
		return errors.New("authentication session candidate capacity exceeded")
	}
	return nil
}
func (s *Session) retain(w *Writer) (Handle, error) {
	charge := w.stateCharge()
	if charge > s.limits.MaxStateBytes-s.charge {
		return Handle{}, errors.New("authentication session state byte limit exceeded")
	}
	s.next++
	id := strconv.FormatUint(s.next, 10)
	s.writers[id] = w
	s.charge += charge
	return Handle{ID: id, Root: w.Root()}, nil
}
func (s *Session) Build(ctx context.Context, state engine.State) (Handle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.capacity(); err != nil {
		return Handle{}, err
	}
	w, err := BuildWriter(ctx, s.engine, state)
	if err != nil {
		return Handle{}, err
	}
	return s.retain(w)
}
func (s *Session) Import(ctx context.Context, candidate protocol.AuthenticationCandidate) (Handle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.capacity(); err != nil {
		return Handle{}, err
	}
	w, err := NewWriter(ctx, s.engine, candidate)
	if err != nil {
		return Handle{}, err
	}
	return s.retain(w)
}
func (s *Session) Apply(ctx context.Context, base string, delta Delta) (Handle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w := s.writers[base]
	if w == nil {
		return Handle{}, errors.New("unknown authentication handle")
	}
	if err := s.capacity(); err != nil {
		return Handle{}, err
	}
	next, err := w.Apply(ctx, delta)
	if err != nil {
		return Handle{}, err
	}
	return s.retain(next)
}
func (s *Session) Export(ctx context.Context, id string) (protocol.AuthenticationCandidate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w := s.writers[id]
	if w == nil {
		return protocol.AuthenticationCandidate{}, errors.New("unknown authentication handle")
	}
	return w.Export(ctx)
}
func (s *Session) Discard(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	w := s.writers[id]
	if w == nil {
		return errors.New("unknown authentication handle")
	}
	s.charge -= w.stateCharge()
	delete(s.writers, id)
	return nil
}
func (s *Session) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writers = make(map[string]*Writer)
	s.charge = 0
}
func (w *Writer) stateCharge() uint64 {
	total := w.nodes.StateCharge()
	if w.bindings != nil {
		if math.MaxUint64-total < w.bindings.charge {
			return math.MaxUint64
		}
		total += w.bindings.charge
	}
	return total
}

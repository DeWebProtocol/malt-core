package memory

import (
	"context"
	"fmt"
	"github.com/dewebprotocol/malt-core/auth/arcset/materializer"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/maltcid"
	"sync"
)

// Nodes is a reference materializer for immutable authentication vectors.
// Its keys include layout/node encoding and VC profile, but never AA.
type Nodes struct {
	mu     sync.RWMutex
	values map[string][]commitment.Cell
}

func NewNodes() *Nodes { return &Nodes{values: make(map[string][]commitment.Cell)} }
func (s *Nodes) GetNode(ctx context.Context, ref maltcid.NodeRef) ([]commitment.Cell, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key, err := ref.Bytes()
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	values, ok := s.values[string(key)]
	if !ok {
		return nil, materializer.ErrIncomplete
	}
	return commitment.CloneCells(values), nil
}
func (s *Nodes) PutNode(ctx context.Context, ref maltcid.NodeRef, cells []commitment.Cell) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	key, err := ref.Bytes()
	if err != nil {
		return err
	}
	p, err := maltcid.Profile(ref.Profile)
	if err != nil {
		return err
	}
	if len(cells) != p.Slots {
		return fmt.Errorf("node width does not match profile")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.values[string(key)]; ok {
		for i := range old {
			if !old[i].Equal(cells[i]) {
				return fmt.Errorf("conflicting materialization for immutable node")
			}
		}
		return nil
	}
	if s.values == nil {
		s.values = make(map[string][]commitment.Cell)
	}
	s.values[string(key)] = commitment.CloneCells(cells)
	return nil
}
func (s *Nodes) Len() int { s.mu.RLock(); defer s.mu.RUnlock(); return len(s.values) }

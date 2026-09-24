package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer"
	"github.com/dewebprotocol/malt-core/maltcid"
	cid "github.com/ipfs/go-cid"
)

// Change supplies an expected old target. Undefined Before means insert and
// undefined After means delete. A batch validates all expectations before any
// new vectors are materialized. It still produces a candidate, not a portable
// proof that the state transition was authorized.
type Change struct {
	Label  []byte
	Before cid.Cid
	After  cid.Cid
}

// ValidateState binds retained application labels to a materialized Root using
// its exact AA. A store cannot substitute a key index for the original labels.
func (e *Engine) ValidateState(ctx context.Context, root cid.Cid, state State, source materializer.NodeLookup) error {
	d, _, err := maltcid.ParseRoot(root)
	if err != nil {
		return err
	}
	if d != state.Descriptor {
		return errors.New("state descriptor differs from Root")
	}
	expected, err := e.Interpret(state)
	if err != nil {
		return err
	}
	actual, err := e.SnapshotBounded(ctx, root, source, uint64(len(expected.Bindings)))
	if err != nil {
		return err
	}
	return matchView(expected, actual)
}

// MatchView compares retained labels with an already authenticated coordinate view.
// It does not authenticate the supplied view; use ValidateState for untrusted nodes.
func (e *Engine) MatchView(state State, actual View) error {
	expected, err := e.Interpret(state)
	if err != nil {
		return err
	}
	return matchView(expected, actual)
}
func matchView(expected, actual View) error {
	if expected.Descriptor != actual.Descriptor {
		return errors.New("state descriptor differs from Root")
	}
	d := expected.Descriptor
	if expected.ChunkSize != actual.ChunkSize || expected.TotalSize != actual.TotalSize || len(expected.Bindings) != len(actual.Bindings) {
		return errors.New("state metadata or count differs from Root")
	}
	sort.Slice(expected.Bindings, func(i, j int) bool {
		a, b := expected.Bindings[i].Coordinate, expected.Bindings[j].Coordinate
		if d.Layout == maltcid.Positional {
			return a.Index < b.Index
		}
		return bytes.Compare(a.Key[:], b.Key[:]) < 0
	})
	for i, b := range expected.Bindings {
		a := actual.Bindings[i]
		if a.Coordinate != b.Coordinate || !a.Target.Equals(b.Target) {
			return fmt.Errorf("state binding %d differs from Root", i)
		}
	}
	return nil
}

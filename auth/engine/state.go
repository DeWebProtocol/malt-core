package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/input"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

// Snapshot reconstructs the complete authenticated-coordinate view. It cannot
// recover original labels from keys. Label enumeration needs retained inputs
// in the caller-owned relation store. Every vector is checked against its ref.
func (e *Engine) Snapshot(ctx context.Context, root cid.Cid, source materializer.NodeLookup) (View, error) {
	return e.SnapshotBounded(ctx, root, source, ^uint64(0))
}

// SnapshotBounded limits logical expansion, including shared Positional
// subtrees. A small materialization must not expand into an enormous view.
func (e *Engine) SnapshotBounded(ctx context.Context, root cid.Cid, source materializer.NodeLookup, maxBindings uint64) (View, error) {
	ref, d, err := maltcid.RootNode(root)
	if err != nil {
		return View{}, err
	}
	s, p, err := e.config(d)
	if err != nil {
		return View{}, err
	}
	if source == nil {
		return View{}, errors.New("node lookup is nil")
	}
	view := View{Descriptor: d}
	visiting := make(map[string]bool)
	var walk func(maltcid.NodeRef, int, *Metadata, []int) error
	walk = func(node maltcid.NodeRef, depth int, expected *Metadata, path []int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if depth >= 256 {
			return errors.New("node depth exceeded")
		}
		key, err := node.Bytes()
		if err != nil {
			return err
		}
		if visiting[string(key)] {
			return errors.New("node cycle")
		}
		visiting[string(key)] = true
		defer delete(visiting, string(key))
		cells, err := source.GetNode(ctx, node)
		if err != nil {
			return err
		}
		if len(cells) != p.Slots {
			return materializer.ErrIncomplete
		}
		// Opening a full supplied vector at its claimed commitment validates the
		// materialization without asking the service to compute a new Root.
		if _, _, err := openVector(s, node, cells, 0); err != nil {
			return err
		}
		var meta Metadata
		start := 0
		if d.Layout == maltcid.Positional {
			meta, err = parseMetadata(cells[0])
			if err != nil {
				return err
			}
			if err := checkMetadata(meta, expected, p.Slots); err != nil {
				return err
			}
			start = 1
			if depth == 0 {
				if meta.Count > maxBindings {
					return fmt.Errorf("snapshot count %d exceeds bound %d", meta.Count, maxBindings)
				}
				view.ChunkSize = meta.ChunkSize
				view.TotalSize = meta.TotalSize
			}
		}
		before := len(view.Bindings)
		for slot := start; slot < len(cells); slot++ {
			cell := cells[slot]
			if d.Layout == maltcid.Positional {
				span, err := subtreeSpan(meta.Height, uint64(p.Slots-1))
				if err != nil {
					return err
				}
				offset := uint64(slot-1) * span
				if uint64(slot-1) > meta.Count/span || offset >= meta.Count {
					if len(cell) != 0 {
						return errors.New("nonempty Positional padding")
					}
					continue
				}
				if len(cell) == 0 {
					return errors.New("hole in Positional state")
				}
				if meta.Height == 0 {
					target, err := parsePositional(cell)
					if err != nil {
						return err
					}
					view.Bindings = append(view.Bindings, CoordinateBinding{Coordinate: input.Coordinate{Kind: input.Index, Index: uint64(len(view.Bindings))}, Target: target})
				} else {
					child, err := parseChild(cell, node)
					if err != nil {
						return err
					}
					childMeta, _, err := childMetadata(meta, offset, p.Slots)
					if err != nil {
						return err
					}
					if err := walk(child, depth+1, &childMeta, nil); err != nil {
						return err
					}
				}
			} else {
				if len(cell) == 0 {
					continue
				}
				if cell[0] == prefixLeaf {
					key, target, err := parsePrefix(cell)
					if err != nil {
						return err
					}
					route := append(append([]int(nil), path...), slot)
					for level, want := range route {
						got, err := digit(key, level, p.Slots)
						if err != nil || got != want {
							return errors.New("leaf is outside its routing prefix")
						}
					}
					if uint64(len(view.Bindings)) >= maxBindings {
						return fmt.Errorf("snapshot exceeds binding bound %d", maxBindings)
					}
					view.Bindings = append(view.Bindings, CoordinateBinding{Coordinate: input.Coordinate{Kind: input.Key, Key: key}, Target: target})
				} else {
					child, err := parseChild(cell, node)
					if err != nil {
						return err
					}
					old := len(view.Bindings)
					if err := walk(child, depth+1, nil, append(append([]int(nil), path...), slot)); err != nil {
						return err
					}
					if len(view.Bindings)-old < 2 {
						return errors.New("noncanonical uncollapsed Prefix node")
					}
				}
			}
		}
		if d.Layout == maltcid.Positional && uint64(len(view.Bindings)-before) != meta.Count {
			return errors.New("Positional subtree count mismatch")
		}
		return nil
	}
	if err := walk(ref, 0, nil, nil); err != nil {
		return View{}, err
	}
	return view, nil
}

// Change supplies an expected old target. Undefined Before means insert and
// undefined After means delete. A batch validates all expectations before any
// new vectors are materialized. It still produces a candidate, not a portable
// proof that the state transition was authorized.
type Change struct {
	Input  input.Value
	Before cid.Cid
	After  cid.Cid
}

// ValidateState binds retained application inputs to a materialized Root using
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

// DiscardNodes permits local candidate reconstruction without retaining the
// generated materialization. It does not assert persistence or acceptance.
type DiscardNodes struct{}

func (DiscardNodes) PutNode(context.Context, maltcid.NodeRef, []commitment.Cell) error { return nil }

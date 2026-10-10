package tree

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/coordinate"
	"github.com/dewebprotocol/malt-core/maltcid"
	cid "github.com/ipfs/go-cid"
)

// Snapshot reconstructs original Prefix labels and their checked coordinates.
// Positional labels are reconstructed from canonical index bytes. Every vector
// is checked against its ref, and Prefix labels must follow their routing paths.
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
	work := newProofWork(source)
	visiting := make(map[string]bool)
	seen := make(map[[32]byte][]byte)
	var walk func(maltcid.NodeRef, int, *position, []int) error
	walk = func(node maltcid.NodeRef, depth int, expected *position, path []int) error {
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
		physical, err := work.load(ctx, node, p.Slots)
		if err != nil {
			return err
		}
		// Verify each physical vector once, but check metadata, routing and
		// logical expansion for every occurrence of a shared subtree.
		if _, _, err := physical.open(ctx, s, 0); err != nil {
			return err
		}
		// Snapshot only opens index zero. Its verified evidence is sufficient
		// for repeats; release the prepared polynomial and its vector copy.
		physical.opening = nil
		cells := physical.cells
		var pos position
		start := 0
		if d.Layout == maltcid.Positional {
			if depth == 0 {
				meta, err := parseMetadata(cells[0])
				if err != nil {
					return err
				}
				if meta.Count > maxBindings {
					return fmt.Errorf("snapshot count %d exceeds bound %d", meta.Count, maxBindings)
				}
				view.PayloadCID = meta.PayloadCID
				pos = rootPosition(meta.Count, p.Slots)
			} else {
				pos = *expected
			}
			start = pos.base()
			if err := checkPosition(cells, pos, p.Slots); err != nil {
				return err
			}
		}
		before := len(view.Bindings)
		for slot := start; slot < len(cells); slot++ {
			cell := cells[slot]
			if d.Layout == maltcid.Positional {
				if slot-start >= pos.used(p.Slots) {
					continue
				}
				if len(cell) == 0 {
					return errors.New("hole in Positional state")
				}
				if pos.height == 0 {
					target, err := parsePositional(cell)
					if err != nil {
						return err
					}
					index := uint64(len(view.Bindings))
					view.Bindings = append(view.Bindings, CoordinateBinding{Coordinate: coordinate.At(index), Label: coordinate.EncodeIndex(index), Target: target})
				} else {
					child, err := parseChild(cell, node)
					if err != nil {
						return err
					}
					childPos, _ := pos.child(slot-start, p.Slots)
					if err := walk(child, depth+1, &childPos, nil); err != nil {
						return err
					}
				}
			} else {
				if len(cell) == 0 {
					continue
				}
				if cell[0] == prefixLeaf {
					label, target, err := parsePrefix(cell)
					if err != nil {
						return err
					}
					key, err := e.labelCoordinate(d, label)
					if err != nil {
						return err
					}
					if previous, exists := seen[key.Key]; exists {
						if !bytes.Equal(previous, label) {
							return ErrCoordinateCollision
						}
					}
					route := append(append([]int(nil), path...), slot)
					for level, want := range route {
						got, err := digit(key.Key, level, p.Slots)
						if err != nil || got != want {
							return errors.New("leaf is outside its routing prefix")
						}
					}
					if _, exists := seen[key.Key]; exists {
						return errors.New("duplicate authentication label")
					}
					seen[key.Key] = label
					if uint64(len(view.Bindings)) >= maxBindings {
						return fmt.Errorf("snapshot exceeds binding bound %d", maxBindings)
					}
					view.Bindings = append(view.Bindings, CoordinateBinding{Coordinate: key, Label: label, Target: target})
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
		if d.Layout == maltcid.Positional && uint64(len(view.Bindings)-before) != pos.count {
			return errors.New("Positional subtree count mismatch")
		}
		return nil
	}
	if err := walk(ref, 0, nil, nil); err != nil {
		return View{}, err
	}
	return view, nil
}

// Change supplies an original label and expected old target at its coordinate.
// Undefined Before means insert; undefined After means delete.
type Change struct {
	Coordinate coordinate.Coordinate
	Label      []byte
	Before     cid.Cid
	After      cid.Cid
}

// DiscardNodes permits local candidate reconstruction without retaining the
// generated materialization. It does not assert persistence or acceptance.
type DiscardNodes struct{}

func (DiscardNodes) PutNode(context.Context, maltcid.NodeRef, []commitment.Cell) error { return nil }

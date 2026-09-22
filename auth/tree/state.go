package tree

import (
	"context"
	"errors"
	"fmt"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/coordinate"
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
	work := newProofWork(source)
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
					view.Bindings = append(view.Bindings, CoordinateBinding{Coordinate: coordinate.Value{Kind: coordinate.Index, Index: uint64(len(view.Bindings))}, Target: target})
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
					view.Bindings = append(view.Bindings, CoordinateBinding{Coordinate: coordinate.Value{Kind: coordinate.Key, Key: key}, Target: target})
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

// Change supplies an expected old target at a derived authentication coordinate.
// Undefined Before means insert; undefined After means delete.
type Change struct {
	Coordinate coordinate.Value
	Before     cid.Cid
	After      cid.Cid
}

// DiscardNodes permits local candidate reconstruction without retaining the
// generated materialization. It does not assert persistence or acceptance.
type DiscardNodes struct{}

func (DiscardNodes) PutNode(context.Context, maltcid.NodeRef, []commitment.Cell) error { return nil }

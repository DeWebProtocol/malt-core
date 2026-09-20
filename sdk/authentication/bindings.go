package authentication

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"math/bits"

	"github.com/dewebprotocol/malt-core/auth/coordinate"
	"github.com/dewebprotocol/malt-core/auth/engine"
)

// bindingNode is an immutable compressed binary trie over authentication
// coordinates. Updates copy at most one bounded path, never the whole input map.
type bindingNode struct {
	charge      uint64
	maximum     [33]byte
	key         [33]byte
	entry       engine.Entry
	coordinate  coordinate.Value
	left, right *bindingNode
	bit         int
	size        uint64
}

func bindingKey(c coordinate.Value) (k [33]byte) {
	if c.Kind == coordinate.Index {
		k[0] = 1
		binary.BigEndian.PutUint64(k[25:], c.Index)
	} else {
		copy(k[1:], c.Key[:])
	}
	return
}
func keyBit(k [33]byte, i int) byte { return k[i/8] >> uint(7-i%8) & 1 }
func bindingGet(n *bindingNode, k [33]byte) *bindingNode {
	for n != nil && n.left != nil {
		if keyBit(k, n.bit) == 0 {
			n = n.left
		} else {
			n = n.right
		}
	}
	if n == nil || n.key != k {
		return nil
	}
	return n
}
func branch(bit int, left, right *bindingNode) *bindingNode {
	return &bindingNode{charge: 256 + left.charge + right.charge, key: left.key, maximum: right.maximum, bit: bit, left: left, right: right, size: left.size + right.size}
}
func bindingSet(n *bindingNode, c coordinate.Value, entry engine.Entry) *bindingNode {
	entry.Input.Data = bytes.Clone(entry.Input.Data)
	leaf := &bindingNode{charge: uint64(256 + len(entry.Input.Data)*2 + len(entry.Target.Bytes())*2), key: bindingKey(c), maximum: bindingKey(c), coordinate: c, entry: entry, size: 1}
	if n == nil {
		return leaf
	}
	old := n
	for old.left != nil {
		if keyBit(leaf.key, old.bit) == 0 {
			old = old.left
		} else {
			old = old.right
		}
	}
	diff := 264
	for i := range leaf.key {
		if x := leaf.key[i] ^ old.key[i]; x != 0 {
			diff = i*8 + bits.LeadingZeros8(x)
			break
		}
	}
	var insert func(*bindingNode) *bindingNode
	insert = func(node *bindingNode) *bindingNode {
		if node.left == nil || node.bit >= diff {
			if diff == 264 {
				return leaf
			}
			if keyBit(leaf.key, diff) == 0 {
				return branch(diff, leaf, node)
			}
			return branch(diff, node, leaf)
		}
		if keyBit(leaf.key, node.bit) == 0 {
			return branch(node.bit, insert(node.left), node.right)
		}
		return branch(node.bit, node.left, insert(node.right))
	}
	return insert(n)
}
func bindingDelete(n *bindingNode, k [33]byte) *bindingNode {
	if n == nil {
		return nil
	}
	if n.left == nil {
		if n.key == k {
			return nil
		}
		return n
	}
	if keyBit(k, n.bit) == 0 {
		l := bindingDelete(n.left, k)
		if l == nil {
			return n.right
		}
		if l == n.left {
			return n
		}
		return branch(n.bit, l, n.right)
	}
	r := bindingDelete(n.right, k)
	if r == nil {
		return n.left
	}
	if r == n.right {
		return n
	}
	return branch(n.bit, n.left, r)
}
func bindingWalk(ctx context.Context, n *bindingNode, f func(*bindingNode) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if n == nil {
		return nil
	}
	if n.left == nil {
		return f(n)
	}
	if err := bindingWalk(ctx, n.left, f); err != nil {
		return err
	}
	return bindingWalk(ctx, n.right, f)
}
func bindingsFromState(ctx context.Context, e *engine.Engine, state engine.State) (*bindingNode, engine.View, error) {
	view, err := e.Interpret(state)
	if err != nil {
		return nil, engine.View{}, err
	}
	var root *bindingNode
	for i, b := range view.Bindings {
		if err := ctx.Err(); err != nil {
			return nil, engine.View{}, err
		}
		if !b.Target.Defined() {
			return nil, engine.View{}, errors.New("undefined binding target")
		}
		if bindingGet(root, bindingKey(b.Coordinate)) != nil {
			return nil, engine.View{}, errors.New("duplicate authentication coordinate")
		}
		root = bindingSet(root, b.Coordinate, state.Entries[i])
	}
	return root, view, nil
}

func bindingBefore(n *bindingNode, limit [33]byte) *bindingNode {
	if n == nil || bytes.Compare(n.key[:], limit[:]) >= 0 {
		return nil
	}
	if bytes.Compare(n.maximum[:], limit[:]) < 0 {
		return n
	}
	left, right := bindingBefore(n.left, limit), bindingBefore(n.right, limit)
	if left == nil {
		return right
	}
	if right == nil {
		return left
	}
	return branch(n.bit, left, right)
}

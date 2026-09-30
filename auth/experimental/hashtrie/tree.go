package hashtrie

import (
	"bytes"
	"context"
	"fmt"
	"sort"

	"github.com/dewebprotocol/malt-core/auth/coordinate"
	cid "github.com/ipfs/go-cid"
)

// Build creates a compact, order-independent tree. It never stores a wide
// sparse vector or a linear proof list. Nodes remain immutable across roots.
func Build(ctx context.Context, kind coordinate.Kind, entries []Entry, store Nodes) (Root, error) {
	if _, err := kindTag(kind); err != nil {
		return Root{}, err
	}
	if len(entries) > 1_000_000 {
		return Root{}, fmt.Errorf("entry budget exceeded")
	}
	type item struct {
		key    []byte
		path   Digest
		target cid.Cid
	}
	items := make([]item, len(entries))
	for i, e := range entries {
		k, err := key(kind, e.Coordinate)
		if err != nil {
			return Root{}, err
		}
		if !e.Target.Defined() {
			return Root{}, fmt.Errorf("build target is absent")
		}
		items[i] = item{k, route(kind, k), e.Target}
	}
	sort.Slice(items, func(i, j int) bool { return bytes.Compare(items[i].path[:], items[j].path[:]) < 0 })
	for i := 1; i < len(items); i++ {
		if items[i-1].path == items[i].path {
			return Root{}, fmt.Errorf("duplicate coordinate or route-hash collision")
		}
	}
	var build func([]item) (Digest, error)
	build = func(xs []item) (Digest, error) {
		if err := ctx.Err(); err != nil {
			return Digest{}, err
		}
		if len(xs) == 0 {
			return empty(kind), nil
		}
		if len(xs) == 1 {
			body, err := leafBody(kind, xs[0].key, xs[0].target)
			if err != nil {
				return Digest{}, err
			}
			return store.put(ctx, kind, body)
		}
		split := shared(xs[0].path, xs[len(xs)-1].path)
		pivot := sort.Search(len(xs), func(i int) bool { return bit(xs[i].path, split) == 1 })
		left, err := build(xs[:pivot])
		if err != nil {
			return Digest{}, err
		}
		right, err := build(xs[pivot:])
		if err != nil {
			return Digest{}, err
		}
		body, err := branchBody(kind, split, prefix(xs[0].path, split), left, right)
		if err != nil {
			return Digest{}, err
		}
		return store.put(ctx, kind, body)
	}
	digest, err := build(items)
	return newRoot(kind, digest), err
}

// Apply validates the complete before target against the selected old root,
// then rewrites only the compact path. An undefined After deletes a binding.
// The returned root is an execution result, not a portable transition proof.
func Apply(ctx context.Context, root Root, change Change, store Nodes) (Root, error) {
	proof, err := Prove(ctx, root, change.Coordinate, store)
	if err != nil {
		return Root{}, err
	}
	before, err := Verify(root, change.Coordinate, proof)
	if err != nil {
		return Root{}, err
	}
	if before.Present != change.Before.Defined() || before.Present && !before.Target.Equals(change.Before) {
		return Root{}, fmt.Errorf("before target differs from selected root")
	}
	k, err := key(root.Kind, change.Coordinate)
	if err != nil {
		return Root{}, err
	}
	path := route(root.Kind, k)
	var update func(Digest) (Digest, error)
	update = func(digest Digest) (Digest, error) {
		if digest == empty(root.Kind) {
			if !change.After.Defined() {
				return digest, nil
			}
			body, err := leafBody(root.Kind, k, change.After)
			if err != nil {
				return Digest{}, err
			}
			return store.put(ctx, root.Kind, body)
		}
		n, _, err := store.get(ctx, root.Kind, digest)
		if err != nil {
			return Digest{}, err
		}
		var representative Digest
		if n.leaf {
			if bytes.Equal(n.key, k) {
				if !change.After.Defined() {
					return empty(root.Kind), nil
				}
				if n.target.Equals(change.After) {
					return digest, nil
				}
				body, err := leafBody(root.Kind, k, change.After)
				if err != nil {
					return Digest{}, err
				}
				return store.put(ctx, root.Kind, body)
			}
			representative = route(root.Kind, n.key)
		} else {
			representative = n.prefix
		}
		if n.leaf || prefix(path, n.split) != n.prefix {
			if !change.After.Defined() {
				return digest, nil
			}
			split := shared(path, representative)
			if split >= 256 {
				return Digest{}, fmt.Errorf("route-hash collision")
			}
			leaf, err := leafBody(root.Kind, k, change.After)
			if err != nil {
				return Digest{}, err
			}
			newLeaf, err := store.put(ctx, root.Kind, leaf)
			if err != nil {
				return Digest{}, err
			}
			left, right := newLeaf, digest
			if bit(path, split) == 1 {
				left, right = digest, newLeaf
			}
			body, err := branchBody(root.Kind, split, prefix(path, split), left, right)
			if err != nil {
				return Digest{}, err
			}
			return store.put(ctx, root.Kind, body)
		}
		old := n.left
		if bit(path, n.split) == 1 {
			old = n.right
		}
		next, err := update(old)
		if err != nil {
			return Digest{}, err
		}
		if next == old {
			return digest, nil
		}
		if bit(path, n.split) == 0 {
			if next == empty(root.Kind) {
				return n.right, nil
			}
			n.left = next
		} else {
			if next == empty(root.Kind) {
				return n.left, nil
			}
			n.right = next
		}
		body, err := branchBody(root.Kind, n.split, n.prefix, n.left, n.right)
		if err != nil {
			return Digest{}, err
		}
		return store.put(ctx, root.Kind, body)
	}
	digest, err := update(root.Digest)
	return newRoot(root.Kind, digest), err
}

package hashtrie

import (
	"bytes"
	"context"
	"fmt"

	"github.com/dewebprotocol/malt-core/auth/coordinate"
)

func Prove(ctx context.Context, root Root, query coordinate.Coordinate, store Nodes) (Proof, error) {
	p := Proof{Schema: ProofSchema, Steps: []Step{}}
	if err := root.Validate(); err != nil {
		return p, err
	}
	k, err := key(root.Kind, query)
	if err != nil {
		return p, err
	}
	p.Key = bytes.Clone(k)
	path := route(root.Kind, k)
	digest := root.Digest
	last := -1
	if digest == empty(root.Kind) {
		tag, _ := kindTag(root.Kind)
		p.Terminal = []byte{0, tag}
		return p, nil
	}
	for {
		n, body, err := store.get(ctx, root.Kind, digest)
		if err != nil {
			return p, err
		}
		if n.leaf {
			p.Terminal = body
			return p, nil
		}
		if int(n.split) <= last {
			return p, fmt.Errorf("untrusted node has non-increasing split")
		}
		if prefix(path, n.split) != n.prefix {
			p.Terminal = body
			return p, nil
		}
		last = int(n.split)
		step := Step{Split: n.split, Prefix: n.prefix, Sibling: n.right}
		digest = n.left
		if bit(path, n.split) == 1 {
			step.Sibling = n.left
			digest = n.right
		}
		p.Steps = append(p.Steps, step)
		if len(p.Steps) > 256 {
			return p, fmt.Errorf("proof budget exceeded")
		}
	}
}

// Verify uses only the selected experimental root, exact query and proof.
// Missing backend state cannot be converted to an absence result.
func Verify(root Root, query coordinate.Coordinate, proof Proof) (Result, error) {
	var result Result
	if err := root.Validate(); err != nil {
		return result, err
	}
	k, err := key(root.Kind, query)
	if err != nil {
		return result, err
	}
	if proof.Schema != ProofSchema || !bytes.Equal(k, proof.Key) || len(proof.Steps) > 256 || len(proof.Terminal) > 8192 {
		return result, fmt.Errorf("proof schema, full query binding or budget mismatch")
	}
	path := route(root.Kind, k)
	last := -1
	for _, step := range proof.Steps {
		if step.Split >= 256 || int(step.Split) <= last || step.Prefix != prefix(path, step.Split) || step.Sibling == empty(root.Kind) {
			return result, fmt.Errorf("invalid compact proof path")
		}
		last = int(step.Split)
	}
	tag, _ := kindTag(root.Kind)
	if bytes.Equal(proof.Terminal, []byte{0, tag}) {
		if len(proof.Steps) != 0 || root.Digest != empty(root.Kind) {
			return result, fmt.Errorf("empty terminal cannot hide a subtree")
		}
		return result, nil
	}
	n, err := parse(root.Kind, proof.Terminal)
	if err != nil {
		return result, err
	}
	if n.leaf {
		leafPath := route(root.Kind, n.key)
		for _, step := range proof.Steps {
			if prefix(leafPath, step.Split) != step.Prefix || bit(leafPath, step.Split) != bit(path, step.Split) {
				return result, fmt.Errorf("terminal leaf is outside selected compact path")
			}
		}
		result.Present = bytes.Equal(n.key, k)
		if result.Present {
			result.Target = n.target
		}
	} else {
		if int(n.split) <= last || prefix(path, n.split) == n.prefix {
			return result, fmt.Errorf("terminal branch does not prove prefix divergence")
		}
		for _, step := range proof.Steps {
			if prefix(n.prefix, step.Split) != step.Prefix || bit(n.prefix, step.Split) != bit(path, step.Split) {
				return result, fmt.Errorf("terminal branch is outside selected compact path")
			}
		}
	}
	digest := hashNode(proof.Terminal)
	for i := len(proof.Steps) - 1; i >= 0; i-- {
		step := proof.Steps[i]
		left, right := digest, step.Sibling
		if bit(path, step.Split) == 1 {
			left, right = step.Sibling, digest
		}
		body, err := branchBody(root.Kind, step.Split, step.Prefix, left, right)
		if err != nil {
			return Result{}, err
		}
		digest = hashNode(body)
	}
	if digest != root.Digest {
		return Result{}, fmt.Errorf("proof does not match selected experimental root")
	}
	return result, nil
}

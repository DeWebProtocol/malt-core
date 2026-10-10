package tree

import (
	"bytes"
	"context"
	"errors"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/maltcid"
	cid "github.com/ipfs/go-cid"
)

const ProofFormat = "malt.binding/1"

type NodeOpening struct {
	Cell          []byte `json:"cell,omitempty"`
	Proof         []byte `json:"proof,omitempty"`
	Metadata      []byte `json:"metadata,omitempty"`
	MetadataProof []byte `json:"metadata_proof,omitempty"`
}
type Proof struct {
	Format string        `json:"format"`
	Nodes  []NodeOpening `json:"nodes"`
}
type Result struct {
	Present bool    `json:"present"`
	Target  cid.Cid `json:"target" schema:"optional,nullable"`
	Proof   Proof   `json:"proof"`
}

func openVector(s Profile, ref maltcid.NodeRef, cells []commitment.Cell, index uint64) (commitment.Cell, []byte, error) {
	opening, err := prepareVector(s, ref, cells)
	if err != nil {
		return nil, nil, err
	}
	return opening.open(index)
}
func verifyOpening(s Profile, ref maltcid.NodeRef, index uint64, cell, proof []byte) (bool, error) {
	root, err := commitment.NewValue(ref.Profile, ref.Commitment)
	if err != nil {
		return false, err
	}
	verifier, ok := s.(commitment.Verifier)
	if !ok {
		return false, errors.New("VC profile cannot verify openings")
	}
	return verifier.VerifyIndex(root, index, commitment.NewCell(cell), bytes.Clone(proof))
}

// Prove authenticates the original label at its checked routing coordinate.
// Storage errors and coordinate collisions are never authenticated absence.
func (e *Engine) Prove(ctx context.Context, root cid.Cid, query Selector, source materializer.NodeLookup) (Result, error) {
	return e.prove(ctx, root, query, newProofWork(source))
}

func (e *Engine) prove(ctx context.Context, root cid.Cid, query Selector, work *proofWork) (Result, error) {
	ref, d, err := maltcid.RootNode(root)
	if err != nil {
		return Result{}, err
	}
	s, p, err := e.config(d)
	if err != nil {
		return Result{}, err
	}
	k, err := e.selector(d, query)
	if err != nil {
		return Result{}, err
	}
	if work.source == nil {
		return Result{}, errors.New("node lookup is nil")
	}
	result := Result{Proof: Proof{Format: ProofFormat, Nodes: []NodeOpening{}}}
	localIndex := k.Index
	var pos position
	for depth := 0; depth < 256; depth++ {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		node, err := work.load(ctx, ref, p.Slots)
		if err != nil {
			return Result{}, err
		}
		opening := NodeOpening{}
		var slot uint64
		if d.Layout == maltcid.Prefix {
			digit, err := digit(k.Key, depth, p.Slots)
			if err != nil {
				return Result{}, err
			}
			slot = uint64(digit)
		} else if depth == 0 {
			opening.Metadata, opening.MetadataProof, err = node.open(ctx, s, 0)
			if err != nil {
				return Result{}, err
			}
			meta, err := parseMetadata(opening.Metadata)
			if err != nil {
				return Result{}, err
			}
			pos = rootPosition(meta.Count, p.Slots)
			if localIndex >= meta.Count {
				result.Proof.Nodes = append(result.Proof.Nodes, opening)
				return result, nil
			}
		}
		if d.Layout == maltcid.Positional {
			slot = uint64(pos.slot(localIndex, p.Slots))
		}
		opening.Cell, opening.Proof, err = node.open(ctx, s, slot)
		if err != nil {
			return Result{}, err
		}
		result.Proof.Nodes = append(result.Proof.Nodes, opening)
		if len(opening.Cell) == 0 {
			if d.Layout == maltcid.Positional {
				return Result{}, errors.New("hole in Positional state")
			}
			return result, nil
		}
		if d.Layout == maltcid.Prefix && opening.Cell[0] == prefixLeaf {
			label, target, err := parsePrefix(opening.Cell)
			if err != nil {
				return Result{}, err
			}
			leaf, err := e.labelCoordinate(d, label)
			if err != nil {
				return Result{}, err
			}
			if err := checkLeafRoute(leaf.Key, k.Key, depth, p.Slots); err != nil {
				return Result{}, err
			}
			if leaf.Key == k.Key && !bytes.Equal(label, query.Label) {
				return Result{}, ErrCoordinateCollision
			}
			result.Present = bytes.Equal(label, query.Label)
			if result.Present {
				result.Target = target
			}
			return result, nil
		}
		if d.Layout == maltcid.Positional && pos.height == 0 {
			result.Target, err = parsePositional(opening.Cell)
			if err != nil {
				return Result{}, err
			}
			result.Present = true
			return result, nil
		}
		ref, err = parseChild(opening.Cell, ref)
		if err != nil {
			return Result{}, err
		}
		if d.Layout == maltcid.Positional {
			next, start := pos.child(int(slot)-pos.base(), p.Slots)
			pos = next
			localIndex -= start
		}
	}
	return Result{}, errors.New("authentication path exceeds maximum depth")
}

// Verify binds evidence to the caller's full Root and exact original label.
// Coordinates select openings, but cannot substitute for label identity.
func (e *Engine) Verify(root cid.Cid, query Selector, result Result) (bool, error) {
	ref, d, err := maltcid.RootNode(root)
	if err != nil {
		return false, err
	}
	s, p, err := e.config(d)
	if err != nil {
		return false, err
	}
	k, err := e.selector(d, query)
	if err != nil {
		return false, err
	}
	if result.Proof.Format != ProofFormat || len(result.Proof.Nodes) == 0 || len(result.Proof.Nodes) > 256 {
		return false, errors.New("invalid binding proof format or length")
	}
	if result.Present != result.Target.Defined() {
		return false, errors.New("presence and target disagree")
	}
	localIndex := k.Index
	var pos position
	for depth, opening := range result.Proof.Nodes {
		last := depth == len(result.Proof.Nodes)-1
		var slot uint64
		if d.Layout == maltcid.Prefix {
			if len(opening.Metadata) != 0 || len(opening.MetadataProof) != 0 {
				return false, nil
			}
			x, err := digit(k.Key, depth, p.Slots)
			if err != nil {
				return false, err
			}
			slot = uint64(x)
		} else if depth == 0 {
			valid, err := verifyOpening(s, ref, 0, opening.Metadata, opening.MetadataProof)
			if err != nil || !valid {
				return valid, err
			}
			meta, err := parseMetadata(opening.Metadata)
			if err != nil {
				return false, err
			}
			pos = rootPosition(meta.Count, p.Slots)
			if localIndex >= meta.Count {
				return depth == 0 && last && !result.Present && len(opening.Cell) == 0 && len(opening.Proof) == 0, nil
			}
		} else if len(opening.Metadata) != 0 || len(opening.MetadataProof) != 0 {
			return false, nil
		}
		if d.Layout == maltcid.Positional {
			slot = uint64(pos.slot(localIndex, p.Slots))
		}
		valid, err := verifyOpening(s, ref, slot, opening.Cell, opening.Proof)
		if err != nil || !valid {
			return valid, err
		}
		if len(opening.Cell) == 0 {
			return d.Layout == maltcid.Prefix && last && !result.Present, nil
		}
		if d.Layout == maltcid.Prefix && opening.Cell[0] == prefixLeaf {
			label, target, err := parsePrefix(opening.Cell)
			if err != nil {
				return false, err
			}
			leaf, err := e.labelCoordinate(d, label)
			if err != nil {
				return false, err
			}
			if err := checkLeafRoute(leaf.Key, k.Key, depth, p.Slots); err != nil {
				return false, err
			}
			if !last {
				return false, nil
			}
			if leaf.Key == k.Key && !bytes.Equal(label, query.Label) {
				return false, ErrCoordinateCollision
			}
			if result.Present {
				return bytes.Equal(label, query.Label) && target.Equals(result.Target), nil
			}
			return !bytes.Equal(label, query.Label) && leaf.Key != k.Key, nil
		}
		if d.Layout == maltcid.Positional && pos.height == 0 {
			target, err := parsePositional(opening.Cell)
			if err != nil {
				return false, err
			}
			return last && result.Present && target.Equals(result.Target), nil
		}
		if last {
			return false, nil
		}
		ref, err = parseChild(opening.Cell, ref)
		if err != nil {
			return false, err
		}
		if d.Layout == maltcid.Positional {
			next, start := pos.child(int(slot)-pos.base(), p.Slots)
			pos = next
			localIndex -= start
		}
	}
	return false, nil
}

func checkLeafRoute(leaf, query [32]byte, depth, slots int) error {
	for d := 0; d <= depth; d++ {
		a, err := digit(leaf, d, slots)
		if err != nil {
			return err
		}
		b, _ := digit(query, d, slots)
		if a != b {
			return errors.New("leaf does not match its routing prefix")
		}
	}
	return nil
}
func parsePositional(cell commitment.Cell) (cid.Cid, error) {
	if len(cell) < 2 || cell[0] != positionalLeaf {
		return cid.Undef, errors.New("invalid Positional target")
	}
	target, err := cid.Cast(cell[1:])
	if err != nil {
		return cid.Undef, err
	}
	if !bytes.Equal(target.Bytes(), cell[1:]) {
		return cid.Undef, errors.New("noncanonical Positional target")
	}
	return target, nil
}

// RootMetadata decodes structural metadata from the first proof node. Callers
// must still Verify the proof against the caller-selected Root before using it.
func (p Proof) RootMetadata() (Metadata, error) {
	if len(p.Nodes) == 0 {
		return Metadata{}, errors.New("missing root metadata")
	}
	return parseMetadata(p.Nodes[0].Metadata)
}

// ValidateNode checks a full vector against its internal identity. It does not
// infer an external Root's AA or a node's tree position from that identity.
func (e *Engine) ValidateNode(ctx context.Context, ref maltcid.NodeRef, cells []commitment.Cell) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := ref.Bytes(); err != nil {
		return err
	}
	if e == nil {
		return errors.New("authentication engine is nil")
	}
	s, err := e.Profiles.lookup(ref.Profile)
	if err != nil {
		return err
	}
	_, _, err = openVector(s, ref, cells, 0)
	return err
}

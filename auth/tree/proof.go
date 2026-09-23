package tree

import (
	"bytes"
	"context"
	"errors"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/coordinate"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

const ProofFormat = "malt.binding/0"

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

// Prove opens only the supplied coordinate. Storage errors are never converted
// into authenticated absence. The caller derives the coordinate from its input.
func (e *Engine) Prove(ctx context.Context, root cid.Cid, query coordinate.Coordinate, source materializer.NodeLookup) (Result, error) {
	return e.prove(ctx, root, query, newProofWork(source))
}

func (e *Engine) prove(ctx context.Context, root cid.Cid, query coordinate.Coordinate, work *proofWork) (Result, error) {
	ref, d, err := maltcid.RootNode(root)
	if err != nil {
		return Result{}, err
	}
	s, p, err := e.config(d)
	if err != nil {
		return Result{}, err
	}
	k, err := checkCoordinate(d, query)
	if err != nil {
		return Result{}, err
	}
	if work.source == nil {
		return Result{}, errors.New("node lookup is nil")
	}
	result := Result{Proof: Proof{Format: ProofFormat, Nodes: []NodeOpening{}}}
	localIndex := k.Index
	var expectedMeta *Metadata
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
		var meta Metadata
		if d.Layout == maltcid.Prefix {
			digit, err := digit(k.Key, depth, p.Slots)
			if err != nil {
				return Result{}, err
			}
			slot = uint64(digit)
		} else {
			opening.Metadata, opening.MetadataProof, err = node.open(ctx, s, 0)
			if err != nil {
				return Result{}, err
			}
			meta, err = parseMetadata(opening.Metadata)
			if err != nil {
				return Result{}, err
			}
			if err := checkMetadata(meta, expectedMeta, p.Slots); err != nil {
				return Result{}, err
			}
			if localIndex >= meta.Count {
				if depth != 0 {
					return Result{}, errors.New("inconsistent child count")
				}
				result.Proof.Nodes = append(result.Proof.Nodes, opening)
				return result, nil
			}
			span, err := subtreeSpan(meta.Height, uint64(p.Slots-1))
			if err != nil {
				return Result{}, err
			}
			slot = localIndex/span + 1
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
			key, target, err := parsePrefix(opening.Cell)
			if err != nil {
				return Result{}, err
			}
			if err := checkLeafRoute(key, k.Key, depth, p.Slots); err != nil {
				return Result{}, err
			}
			result.Present = key == k.Key
			if result.Present {
				result.Target = target
			}
			return result, nil
		}
		if d.Layout == maltcid.Positional && meta.Height == 0 {
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
			next, index, err := childMetadata(meta, localIndex, p.Slots)
			if err != nil {
				return Result{}, err
			}
			expectedMeta = &next
			localIndex = index
		}
	}
	return Result{}, errors.New("authentication path exceeds maximum depth")
}

// Verify binds evidence to the caller's full Root and authentication coordinate.
// It consumes no node materializer; callers must derive their own coordinates.
func (e *Engine) Verify(root cid.Cid, query coordinate.Coordinate, result Result) (bool, error) {
	ref, d, err := maltcid.RootNode(root)
	if err != nil {
		return false, err
	}
	s, p, err := e.config(d)
	if err != nil {
		return false, err
	}
	k, err := checkCoordinate(d, query)
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
	var expectedMeta *Metadata
	for depth, opening := range result.Proof.Nodes {
		last := depth == len(result.Proof.Nodes)-1
		var meta Metadata
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
		} else {
			valid, err := verifyOpening(s, ref, 0, opening.Metadata, opening.MetadataProof)
			if err != nil || !valid {
				return valid, err
			}
			meta, err = parseMetadata(opening.Metadata)
			if err != nil {
				return false, err
			}
			if err := checkMetadata(meta, expectedMeta, p.Slots); err != nil {
				return false, err
			}
			if localIndex >= meta.Count {
				return depth == 0 && last && !result.Present && len(opening.Cell) == 0 && len(opening.Proof) == 0, nil
			}
			span, err := subtreeSpan(meta.Height, uint64(p.Slots-1))
			if err != nil {
				return false, err
			}
			slot = localIndex/span + 1
		}
		valid, err := verifyOpening(s, ref, slot, opening.Cell, opening.Proof)
		if err != nil || !valid {
			return valid, err
		}
		if len(opening.Cell) == 0 {
			return d.Layout == maltcid.Prefix && last && !result.Present, nil
		}
		if d.Layout == maltcid.Prefix && opening.Cell[0] == prefixLeaf {
			key, target, err := parsePrefix(opening.Cell)
			if err != nil {
				return false, err
			}
			if err := checkLeafRoute(key, k.Key, depth, p.Slots); err != nil {
				return false, err
			}
			if !last {
				return false, nil
			}
			if result.Present {
				return key == k.Key && target.Equals(result.Target), nil
			}
			return key != k.Key, nil
		}
		if d.Layout == maltcid.Positional && meta.Height == 0 {
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
			next, index, err := childMetadata(meta, localIndex, p.Slots)
			if err != nil {
				return false, err
			}
			expectedMeta = &next
			localIndex = index
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
func checkMetadata(meta Metadata, expected *Metadata, slots int) error {
	if expected != nil {
		if meta != *expected {
			return errors.New("child metadata does not match parent")
		}
		return nil
	}
	h, err := height(meta.Count, uint64(slots-1))
	if err != nil {
		return err
	}
	if meta.Height != h {
		return errors.New("noncanonical Positional root height")
	}
	return nil
}
func childMetadata(parent Metadata, index uint64, slots int) (Metadata, uint64, error) {
	if parent.Height == 0 {
		return Metadata{}, 0, errors.New("leaf has no internal child")
	}
	span, err := subtreeSpan(parent.Height, uint64(slots-1))
	if err != nil {
		return Metadata{}, 0, err
	}
	start := (index / span) * span
	child := parent
	child.Height--
	child.Count = min(span, parent.Count-start)
	if parent.ChunkSize > 0 {
		remaining := parent.TotalSize - start*parent.ChunkSize
		child.TotalSize = remaining
		if child.Count <= remaining/parent.ChunkSize {
			child.TotalSize = child.Count * parent.ChunkSize
		}
	}
	return child, index - start, nil
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

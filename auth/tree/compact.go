package tree

import (
	"bytes"
	"errors"
	"math/bits"

	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/internal/proofwire"
	"github.com/dewebprotocol/malt-core/maltcid"
	cid "github.com/ipfs/go-cid"
)

// TransferBindingProof projects a binding to or from a ProofList stream. The
// enclosing codec supplies the independently derived selector and the claimed
// target (undefined for absence). shared is the root metadata opening already
// carried by a List range. Decoding is structural, never authentication.
func TransferBindingProof(s *proofwire.Stream, d maltcid.RootDescriptor, query Selector, target cid.Cid, proof *Proof, shared *NodeOpening) error {
	profile, err := maltcid.Profile(d.Profile)
	if err != nil {
		return err
	}
	key, err := checkCoordinate(d, query.Coordinate)
	if err != nil {
		return err
	}
	if !s.Reading && proof.Format != ProofFormat {
		return errors.New("invalid binding proof format")
	}
	h := s.Uint(uint64(len(proof.Nodes)))
	// Map consumes one radix digit per vector. List addresses at most 64 bits.
	radix := bits.TrailingZeros(uint(profile.Slots))
	maxDepth := (256 + radix - 1) / radix
	if d.Layout == maltcid.List {
		maxDepth = 1 + (64+radix-1)/radix
	}
	if h == 0 || h > uint64(maxDepth) {
		return errors.New("invalid ProofList path length")
	}
	if s.Reading {
		*proof = Proof{Format: ProofFormat, Nodes: make([]NodeOpening, int(h))}
	}

	var pos listGeometry
	index := key.Index
	for depth := range int(h) {
		node := proof.Nodes[depth]
		if d.Layout == maltcid.List && depth == 0 {
			if err := transferRootMetadata(s, profile.ID, &node, shared); err != nil {
				return err
			}
			meta, err := parseMetadata(node.Metadata)
			if err != nil {
				return err
			}
			pos = listRootGeometry(meta.Count, profile.Slots)
			if index >= meta.Count {
				if h != 1 || target.Defined() || len(node.Cell) != 0 || len(node.Proof) != 0 {
					return errors.New("invalid List bounds proof")
				}
				if s.Reading {
					proof.Nodes[0] = node
				}
				return nil
			}
			if h > uint64(pos.height)+1 || (target.Defined() && h != uint64(pos.height)+1) {
				return errors.New("incorrect List path length")
			}
		} else if len(node.Metadata) != 0 || len(node.MetadataProof) != 0 {
			return errors.New("unexpected node metadata")
		}

		var slot int
		if d.Layout == maltcid.Map {
			slot, err = mapSlot(key.Key, depth, profile.Slots)
			if err != nil {
				return err
			}
		} else {
			slot = pos.slot(index, profile.Slots)
		}

		last := depth == int(h)-1
		var cell commitment.Cell
		if last {
			cell, err = terminalWitnessCell(s, d.Layout, query.Label, target, node.Cell)
		} else {
			cell, err = childWitnessCell(s, d, profile.CommitmentSize, node.Cell)
		}
		if err != nil {
			return err
		}
		if !s.Reading && !bytes.Equal(node.Cell, cell) {
			return errors.New("opened cell disagrees with binding")
		}
		if d.Layout == maltcid.List && len(cell) == 0 && pos.tail && slot-pos.base() == pos.used(profile.Slots)-1 {
			return errors.New("List count extends past its last binding")
		}
		node.Cell = cell
		node.Proof, err = transferOpening(s, d.Profile, uint64(slot), cell, node.Proof)
		if err != nil {
			return err
		}
		if s.Reading {
			proof.Nodes[depth] = node
		}
		if d.Layout == maltcid.List && !last {
			child, start := pos.child(slot-pos.base(), profile.Slots)
			pos = child
			index -= start
		}
	}
	return s.Err
}

func transferRootMetadata(s *proofwire.Stream, profile maltcid.ProfileID, node *NodeOpening, shared *NodeOpening) error {
	if shared != nil {
		if !s.Reading && (!bytes.Equal(node.Metadata, shared.Metadata) || !bytes.Equal(node.MetadataProof, shared.MetadataProof)) {
			return errors.New("range segment disagrees with shared metadata proof")
		}
		node.Metadata, node.MetadataProof = shared.Metadata, shared.MetadataProof
		return nil
	}
	node.Metadata = s.Blob(node.Metadata)
	if s.Err != nil {
		return s.Err
	}
	if s.Reading {
		node.Metadata = bytes.Clone(node.Metadata)
	}
	proof, err := transferOpening(s, profile, 0, node.Metadata, node.MetadataProof)
	node.MetadataProof = proof
	return err
}

func childWitnessCell(s *proofwire.Stream, d maltcid.RootDescriptor, width int, original []byte) (commitment.Cell, error) {
	ref := maltcid.NodeRef{Layout: d.Layout, Profile: d.Profile}
	if !s.Reading {
		child, err := parseChild(original, ref)
		if err != nil {
			return nil, err
		}
		ref = child
	}
	ref.Commitment = s.Fixed(ref.Commitment, width)
	if s.Err != nil {
		return nil, s.Err
	}
	return childCell(ref)
}

func terminalWitnessCell(s *proofwire.Stream, layout maltcid.Layout, label []byte, target cid.Cid, original []byte) (commitment.Cell, error) {
	if target.Defined() {
		if layout == maltcid.Map {
			return mapCell(binding{label: label, target: target}), nil
		}
		return append(commitment.Cell{listLeaf}, target.Bytes()...), nil
	}
	if layout == maltcid.List {
		return nil, nil
	}
	// A missing Map slot is empty or opens a different routed leaf.
	cell := s.Blob(original)
	if s.Err != nil {
		return nil, s.Err
	}
	if len(cell) != 0 {
		other, _, err := parseMap(cell)
		if err != nil {
			return nil, err
		}
		if bytes.Equal(other, label) {
			return nil, errors.New("Map absence opens the requested label")
		}
	}
	return bytes.Clone(cell), nil
}

func transferOpening(s *proofwire.Stream, id maltcid.ProfileID, slot uint64, cell commitment.Cell, proof []byte) ([]byte, error) {
	if s.Reading {
		witness := s.Fixed(nil, commitment.WitnessSize(id))
		if s.Err != nil {
			return nil, s.Err
		}
		return commitment.ExpandIndexWitness(id, slot, cell, witness)
	}
	witness, err := commitment.IndexWitness(id, slot, cell, proof)
	if err != nil {
		return nil, err
	}
	s.Fixed(witness, len(witness))
	return proof, s.Err
}

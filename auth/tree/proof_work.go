package tree

import (
	"bytes"
	"context"
	"errors"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/observation"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
)

// proofWork belongs to one binding/range query. It loads each touched vector
// once and reuses its auxiliary opening material and verified index evidence.
// Nothing survives the call or changes the caller's storage/cache policy.
type proofWork struct {
	source materializer.NodeLookup
	nodes  map[string]*proofNode
}
type proofNode struct {
	ref      maltcid.NodeRef
	cells    []commitment.Cell
	opening  *vectorOpening
	verified map[uint64]indexEvidence
}
type indexEvidence struct {
	cell  commitment.Cell
	proof []byte
}

func newProofWork(source materializer.NodeLookup) *proofWork {
	return &proofWork{source: source, nodes: make(map[string]*proofNode)}
}
func (w *proofWork) load(ctx context.Context, ref maltcid.NodeRef, slots int) (*proofNode, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key, err := ref.Bytes()
	if err != nil {
		return nil, err
	}
	if node := w.nodes[string(key)]; node != nil {
		return node, nil
	}
	finish := observation.Start(ctx, observation.PhaseMaterialization)
	cells, err := w.source.GetNode(ctx, copyNodeRef(ref))
	var cellBytes uint64
	if observation.Enabled(ctx) {
		for _, cell := range cells {
			cellBytes += uint64(len(cell))
		}
	}
	finish(1, uint64(len(cells)), cellBytes)
	if err != nil {
		return nil, err
	}
	if len(cells) != slots {
		return nil, materializer.ErrIncomplete
	}
	node := &proofNode{ref: copyNodeRef(ref), cells: commitment.CloneCells(cells), verified: make(map[uint64]indexEvidence)}
	w.nodes[string(key)] = node
	return node, nil
}
func (n *proofNode) open(ctx context.Context, profile Profile, index uint64) (commitment.Cell, []byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if evidence, ok := n.verified[index]; ok {
		return commitment.NewCell(evidence.cell), bytes.Clone(evidence.proof), nil
	}
	finish := observation.Start(ctx, observation.PhaseOpen)
	var err error
	if n.opening == nil {
		n.opening, err = prepareVector(profile, n.ref, n.cells)
	}
	var cell commitment.Cell
	var proof []byte
	if err == nil {
		cell, proof, err = n.opening.open(index)
	}
	finish(1, 1, uint64(len(proof)))
	if err != nil {
		return nil, nil, err
	}
	// Only verified evidence is reusable. Return detached slices so modifying
	// one segment cannot change another segment or its metadata evidence.
	n.verified[index] = indexEvidence{cell: cell, proof: proof}
	return commitment.NewCell(cell), bytes.Clone(proof), nil
}

type vectorOpening struct {
	root     commitment.Value
	cells    []commitment.Cell
	verifier commitment.Verifier
	prepared commitment.Opening
	prover   commitment.Prover
}

func prepareVector(profile Profile, ref maltcid.NodeRef, cells []commitment.Cell) (*vectorOpening, error) {
	root, err := commitment.NewValue(ref.Profile, ref.Commitment)
	if err != nil {
		return nil, err
	}
	if len(cells) != profile.MaxValues() {
		return nil, errors.New("materialized vector width mismatch")
	}
	verifier, ok := profile.(commitment.Verifier)
	if !ok {
		return nil, errors.New("VC profile cannot verify openings")
	}
	opening := &vectorOpening{root: root, cells: cells, verifier: verifier}
	if preparer, ok := profile.(commitment.PreparedProver); ok {
		opening.prepared, err = preparer.PrepareOpening(root, commitment.CloneCells(cells))
		if err != nil {
			return nil, err
		}
		if opening.prepared == nil || !opening.prepared.Root().Equals(root) {
			return nil, errors.New("opening does not bind the selected commitment")
		}
	} else {
		opening.prover, ok = profile.(commitment.Prover)
		if !ok {
			return nil, errors.New("VC profile cannot generate openings")
		}
	}
	return opening, nil
}
func (o *vectorOpening) open(index uint64) (commitment.Cell, []byte, error) {
	if index >= uint64(len(o.cells)) {
		return nil, nil, errors.New("materialized vector index out of range")
	}
	var cell commitment.Cell
	var proof []byte
	var err error
	if o.prepared != nil {
		cell, proof, err = o.prepared.Open(index)
	} else {
		cell, proof, err = o.prover.Prove(o.root, commitment.CloneCells(o.cells), index)
	}
	if err != nil {
		return nil, nil, err
	}
	if !cell.Equal(o.cells[index]) {
		return nil, nil, errors.New("prover returned a different cell")
	}
	valid, err := o.verifier.VerifyIndex(o.root, index, commitment.NewCell(cell), bytes.Clone(proof))
	if err != nil {
		return nil, nil, err
	}
	if !valid {
		return nil, nil, materializer.ErrIncomplete
	}
	return commitment.NewCell(cell), bytes.Clone(proof), nil
}

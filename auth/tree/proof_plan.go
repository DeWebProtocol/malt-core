package tree

import (
	"context"
	"errors"
	"runtime"

	"github.com/dewebprotocol/malt-core/auth/commitment"
	"golang.org/x/sync/errgroup"
)

type openingDestination struct {
	index    uint64
	position int
	metadata bool
}

type plannedVector struct {
	node         *proofNode
	destinations []openingDestination
}

// Planning reads storage serially and detaches selected cells before any
// cryptographic work starts. Each distinct vector has one job, so its prepared
// opening and verified-index cache need no concurrent mutation. Multiple
// requests against one vector remain in that job and reuse the existing cache.
type proofPlan struct {
	vectors []*plannedVector
	byNode  map[*proofNode]*plannedVector
}

func newProofPlan() *proofPlan { return &proofPlan{byNode: make(map[*proofNode]*plannedVector)} }

func (p *proofPlan) selectCell(node *proofNode, index uint64, position int, metadata bool) (commitment.Cell, error) {
	if index >= uint64(len(node.cells)) {
		return nil, errors.New("planned opening index out of range")
	}
	vector := p.byNode[node]
	if vector == nil {
		vector = &plannedVector{node: node}
		p.byNode[node] = vector
		p.vectors = append(p.vectors, vector)
	}
	vector.destinations = append(vector.destinations, openingDestination{index, position, metadata})
	return commitment.NewCell(node.cells[index]), nil
}

func (p *proofPlan) finish(ctx context.Context, profile Profile, result Result) (Result, error) {
	open := func(ctx context.Context, vector *plannedVector) error {
		for _, destination := range vector.destinations {
			cell, proof, err := vector.node.open(ctx, profile, destination.index)
			if err != nil {
				return err
			}
			node := &result.Proof.Nodes[destination.position]
			if destination.metadata {
				node.Metadata, node.MetadataProof = cell, proof
			} else {
				node.Cell, node.Proof = cell, proof
			}
		}
		return nil
	}
	limit := min(len(p.vectors), runtime.GOMAXPROCS(0))
	if limit <= 1 {
		for _, vector := range p.vectors {
			if err := open(ctx, vector); err != nil {
				return Result{}, err
			}
		}
	} else {
		group, proofCtx := errgroup.WithContext(ctx)
		group.SetLimit(limit)
		for _, vector := range p.vectors {
			group.Go(func() error { return open(proofCtx, vector) })
		}
		if err := group.Wait(); err != nil {
			return Result{}, err
		}
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	return result, nil
}

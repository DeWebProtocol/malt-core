package artifact

import (
	"context"
	"fmt"

	malt "github.com/dewebprotocol/malt-core"
	cid "github.com/ipfs/go-cid"
)

// Verify validates the request/artifact envelope and all cryptographic
// evidence. Resolution is existential: it proves the returned ordered arc
// chain, not that the execution engine selected a unique or longest chain.
func Verify(ctx context.Context, req VerifyRequest, verifier malt.ProofVerifier) error {
	if verifier == nil {
		return fmt.Errorf("artifact verifier is nil")
	}
	if err := req.Validate(); err != nil {
		return err
	}

	root, _ := cid.Parse(req.Artifact.Root)
	target, _ := cid.Parse(req.Artifact.Target)
	switch req.Artifact.Operation {
	case OperationResolve:
		return malt.VerifyResolve(ctx, malt.ResolveRequest{
			Root:     root,
			Segments: req.Artifact.Query.Segments,
		}, malt.ResolveResult{
			Target:    target,
			ProofList: req.Artifact.ProofList,
		}, verifier)
	case OperationProve:
		lastTarget, err := req.Artifact.ProofList.LastStepTarget()
		if err != nil {
			return err
		}
		if !lastTarget.Equals(target) {
			return fmt.Errorf("artifact ProofList target does not match artifact target")
		}
		query, err := req.Artifact.Query.Core()
		if err != nil {
			return err
		}
		segments := make([]cid.Cid, len(req.Artifact.RangeSegments))
		for i, raw := range req.Artifact.RangeSegments {
			segments[i], _ = cid.Parse(raw)
		}
		return malt.VerifyRead(ctx, malt.ReadRequest{Root: root, Query: query}, malt.ReadResult{
			Target:    target,
			Segments:  segments,
			ProofList: req.Artifact.ProofList,
		}, verifier)
	default:
		return fmt.Errorf("unsupported artifact operation %q", req.Artifact.Operation)
	}
}

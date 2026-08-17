// Package resolver implements the MALT explicit-arc resolution loop with
// prefix consumption.
package resolver

import (
	"context"
	"fmt"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	"github.com/dewebprotocol/malt-core/auth/proof/evidence"
	"github.com/dewebprotocol/malt-core/graph/resolver/step"
	"github.com/dewebprotocol/malt-core/graph/resolver/step/explicit"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

type Resolver struct {
	explicitStep step.Step
}

// NewResolver creates a new MALT-native resolver with an explicit step executor.
func NewResolver(explicit step.Step) *Resolver {
	return &Resolver{
		explicitStep: explicit,
	}
}

// ResolveResult contains the result of a resolution operation.
type ResolveResult struct {
	// Target is the final resolved CID
	Target cid.Cid

	// RemainingPath is non-empty when resolution stopped before consuming the
	// requested path.
	RemainingPath arcset.Path

	// Transcript contains the evidence for each step
	Transcript *Transcript
}

// ResolveKey resolves a path to its terminal typed key without terminal payload
// materialization. For list roots, traversal is terminal (no auto @payload).
func (r *Resolver) ResolveKey(ctx context.Context, root cid.Cid, path string) (*ResolveResult, error) {
	if !root.Defined() {
		return nil, ErrUndefinedRoot
	}

	transcript := &Transcript{Steps: make([]StepEvidence, 0)}
	currentCID := root
	remainingPath := arcset.CanonicalizePath(path)

	for !remainingPath.IsEmpty() {
		// Typed list roots are terminal for path traversal.
		if maltcid.SemanticKindOf(currentCID) == maltcid.SemanticKindList {
			return &ResolveResult{
				Target:        currentCID,
				RemainingPath: remainingPath,
				Transcript:    transcript,
			}, nil
		}

		var matchedPath arcset.Path
		var target cid.Cid
		var ev evidence.Evidence
		var err error

		if !maltcid.IsMaltCid(currentCID) || r.explicitStep == nil {
			return &ResolveResult{
				Target:        currentCID,
				RemainingPath: remainingPath,
				Transcript:    transcript,
			}, nil
		}
		matchedPath, target, ev, err = r.explicitStep.Resolve(ctx, currentCID, remainingPath)

		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrResolutionFailed, err)
		}

		// If no path was matched, we can't continue.
		if matchedPath.IsEmpty() {
			return &ResolveResult{
				Target:        currentCID,
				RemainingPath: remainingPath,
				Transcript:    transcript,
			}, nil
		}

		// Record step.
		transcript.Steps = append(transcript.Steps, StepEvidence{
			Path:     matchedPath,
			Target:   target,
			Evidence: ev,
		})

		// Update current CID.
		currentCID = target

		// Update remaining path.
		nextPath, ok := remainingPath.Consume(matchedPath)
		if !ok {
			return nil, fmt.Errorf("%w: failed to consume matched path %q from %q", ErrResolutionFailed, matchedPath.String(), remainingPath.String())
		}
		remainingPath = nextPath
	}

	return &ResolveResult{
		Target:        currentCID,
		RemainingPath: remainingPath,
		Transcript:    transcript,
	}, nil
}

// Resolve is the compatibility materializing resolver. It first performs
// generic explicit relation traversal, then follows a terminal @payload
// binding for map roots. Use ResolveKey when a generic map may omit @payload.
// It stops with RemainingPath set when it reaches a non-MALT CID, a terminal
// list root, or a root with no matching explicit arc.
func (r *Resolver) Resolve(ctx context.Context, root cid.Cid, path string) (*ResolveResult, error) {
	keyResult, err := r.ResolveKey(ctx, root, path)
	if err != nil {
		return nil, err
	}
	if !keyResult.RemainingPath.IsEmpty() {
		return keyResult, nil
	}

	// Terminal materialization is map-only. List roots must remain terminal.
	if maltcid.SemanticKindOf(keyResult.Target) == maltcid.SemanticKindMap && r.explicitStep != nil {
		_, target, ev, err := r.explicitStep.Resolve(ctx, keyResult.Target, explicit.PayloadArc)
		if err != nil {
			return nil, fmt.Errorf("%w: map root %s cannot be materialized through @payload: %w", ErrResolutionFailed, keyResult.Target.String(), err)
		}
		keyResult.Transcript.Steps = append(keyResult.Transcript.Steps, StepEvidence{
			Path:     explicit.PayloadArc,
			Target:   target,
			Evidence: ev,
		})
		return &ResolveResult{
			Target:        target,
			RemainingPath: "",
			Transcript:    keyResult.Transcript,
		}, nil
	}

	return keyResult, nil
}

// VerifyTranscript verifies all steps in a transcript.
func (r *Resolver) VerifyTranscript(ctx context.Context, root cid.Cid, transcript *Transcript) (bool, error) {
	if transcript == nil {
		return false, ErrTranscriptNil
	}

	currentRoot := root

	for _, stepEv := range transcript.Steps {
		var s step.Step
		switch stepEv.Evidence.Kind() {
		case evidence.EvidenceKindExplicit:
			s = r.explicitStep
		default:
			return false, fmt.Errorf("%w: %v", ErrUnknownEvidenceKind, stepEv.Evidence.Kind())
		}

		if s == nil {
			return false, fmt.Errorf("%w for evidence kind: %v", ErrStepExecutorNotAvailable, stepEv.Evidence.Kind())
		}

		valid, err := s.Verify(ctx, currentRoot, stepEv.Path, stepEv.Target, stepEv.Evidence)
		if err != nil {
			return false, fmt.Errorf("verification failed: %w", err)
		}
		if !valid {
			return false, nil
		}
		currentRoot = stepEv.Target
	}

	return true, nil
}

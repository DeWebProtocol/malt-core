package malt

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	"github.com/dewebprotocol/malt-core/auth/proof/prooflist"
	cid "github.com/ipfs/go-cid"
)

// ProofVerifier is the portable verifier surface consumed by clients. An
// implementation must not require ArcTable, CAS, server, or executor state.
type ProofVerifier interface {
	VerifyProofList(context.Context, prooflist.ProofList) (bool, error)
}

// VerifyResolve validates a complete path-resolution result against the
// caller-selected root and segment sequence. ProofList is evidence for the
// result, not the source of the caller's trust inputs.
func VerifyResolve(ctx context.Context, req ResolveRequest, result ResolveResult, verifier ProofVerifier) error {
	if verifier == nil {
		return fmt.Errorf("portable MALT verifier is nil")
	}
	if err := req.Validate(); err != nil {
		return err
	}
	path, _ := NewSegmentPath(req.Segments)
	if !result.ProofList.Root.Equals(req.Root) {
		return fmt.Errorf("ProofList root does not match trusted root")
	}
	if result.ProofList.Query != path.String() {
		return fmt.Errorf("ProofList query %q does not match segment path %q", result.ProofList.Query, path.String())
	}
	if path.Empty() {
		if len(result.ProofList.Steps) != 0 {
			return fmt.Errorf("root identity result contains traversal evidence")
		}
		if !result.Target.Equals(req.Root) {
			return fmt.Errorf("root identity target does not match trusted root")
		}
		return nil
	}
	if err := result.ProofList.ValidateShape(prooflist.RequireSteps()); err != nil {
		return err
	}

	parts := make([]string, 0, len(result.ProofList.Steps))
	var target cid.Cid
	for i, step := range result.ProofList.Steps {
		switch step.Kind {
		case prooflist.KindMapStep:
			part := arcset.CanonicalizePath(step.Path).String()
			if part == "" || part == arcset.PayloadPath.String() {
				return fmt.Errorf("resolve proof step %d has invalid map path %q", i, step.Path)
			}
			parts = append(parts, part)
			target = step.Target
		case prooflist.KindPayloadBinding:
			if arcset.CanonicalizePath(step.Path) != arcset.PayloadPath {
				return fmt.Errorf("resolve proof step %d does not select @payload", i)
			}
			parts = append(parts, arcset.PayloadPath.String())
			target = step.Target
		case prooflist.KindListIndex, prooflist.KindListRange:
			return fmt.Errorf("resolve result contains primitive read evidence at step %d", i)
		default:
			return fmt.Errorf("resolve proof step %d has unsupported kind %q", i, step.Kind)
		}
	}
	if actual := strings.Join(parts, PathSeparator); actual != path.String() {
		return fmt.Errorf("resolve proof path %q does not match segment path %q", actual, path.String())
	}
	if !result.Target.Defined() || !target.Equals(result.Target) {
		return fmt.Errorf("ProofList target does not match resolve result")
	}
	valid, err := verifier.VerifyProofList(ctx, result.ProofList)
	if err != nil {
		return err
	}
	if !valid {
		return ErrVerifierRejected
	}
	return nil
}

// VerifyRead validates the complete verifier-facing read contract.
func VerifyRead(ctx context.Context, req ReadRequest, result ReadResult, verifier ProofVerifier) error {
	if verifier == nil {
		return fmt.Errorf("portable MALT verifier is nil")
	}
	if !req.Root.Defined() {
		return fmt.Errorf("trusted root is undefined")
	}
	if err := req.Query.Validate(); err != nil {
		return err
	}
	if !result.ProofList.Root.Equals(req.Root) {
		return fmt.Errorf("ProofList root does not match trusted root")
	}
	if result.ProofList.Query != req.Query.String() {
		return fmt.Errorf("ProofList query %q does not match request %q", result.ProofList.Query, req.Query.String())
	}
	lastTarget, err := result.ProofList.LastStepTarget()
	if err != nil {
		return err
	}
	if err := validateQueryProofStep(req.Query, result.ProofList.Steps); err != nil {
		return err
	}
	if !result.Target.Defined() || !lastTarget.Equals(result.Target) {
		return fmt.Errorf("ProofList target does not match read result")
	}
	if req.Query.Kind == QueryListRange {
		last := result.ProofList.Steps[len(result.ProofList.Steps)-1]
		if !slices.EqualFunc(last.Segments, result.Segments, func(a, b cid.Cid) bool { return a.Equals(b) }) {
			return fmt.Errorf("ProofList segments do not match read result")
		}
	} else if len(result.Segments) != 0 {
		return fmt.Errorf("read result segments are only valid for list-range queries")
	}
	valid, err := verifier.VerifyProofList(ctx, result.ProofList)
	if err != nil {
		return err
	}
	if !valid {
		return ErrVerifierRejected
	}
	return nil
}

// VerifyMapProof validates a membership or non-membership proof against the
// caller-selected root and key.
func VerifyMapProof(ctx context.Context, req MapProofRequest, result MapProofResult, verifier ProofVerifier) error {
	if verifier == nil {
		return fmt.Errorf("portable MALT verifier is nil")
	}
	if err := req.Validate(); err != nil {
		return err
	}
	if !result.ProofList.Root.Equals(req.Root) {
		return fmt.Errorf("ProofList root does not match trusted root")
	}
	if result.ProofList.Query != req.Key.String() {
		return fmt.Errorf("ProofList query %q does not match map key %q", result.ProofList.Query, req.Key)
	}
	if len(result.ProofList.Steps) != 1 {
		return fmt.Errorf("map proof requires exactly one ProofList step, got %d", len(result.ProofList.Steps))
	}
	step := result.ProofList.Steps[0]
	if arcset.CanonicalizePath(step.Path) != req.Key {
		return fmt.Errorf("map proof path %q does not match %q", step.Path, req.Key)
	}
	if result.Present {
		wantKind := prooflist.KindMapStep
		if req.Key == arcset.PayloadPath {
			wantKind = prooflist.KindPayloadBinding
		}
		if step.Kind != wantKind {
			return fmt.Errorf("present map proof kind %q does not match %q", step.Kind, wantKind)
		}
		if !result.Target.Defined() || !step.Target.Equals(result.Target) {
			return fmt.Errorf("ProofList target does not match present map result")
		}
	} else {
		if step.Kind != prooflist.KindMapAbsence {
			return fmt.Errorf("absent map proof has kind %q, want %q", step.Kind, prooflist.KindMapAbsence)
		}
		if result.Target.Defined() || step.Target.Defined() {
			return fmt.Errorf("absent map proof must not carry a target")
		}
	}
	valid, err := verifier.VerifyProofList(ctx, result.ProofList)
	if err != nil {
		return err
	}
	if !valid {
		return ErrVerifierRejected
	}
	return nil
}

func validateQueryProofStep(query Query, steps []prooflist.Step) error {
	if len(steps) != 1 {
		return fmt.Errorf("typed arc query requires exactly one ProofList step, got %d", len(steps))
	}
	step := steps[0]
	switch query.Kind {
	case QueryMapKey:
		wantKind := prooflist.KindMapStep
		if query.Key == arcset.PayloadPath {
			wantKind = prooflist.KindPayloadBinding
		}
		if step.Kind != wantKind {
			return fmt.Errorf("map query proof kind %q does not match %q", step.Kind, wantKind)
		}
		if arcset.CanonicalizePath(step.Path) != query.Key {
			return fmt.Errorf("map query proof path %q does not match %q", step.Path, query.Key)
		}
	case QueryListIndex:
		if step.Kind != prooflist.KindListIndex || step.Index == nil || *step.Index != query.Index {
			return fmt.Errorf("list-index proof does not match index %d", query.Index)
		}
	case QueryListRange:
		if step.Kind != prooflist.KindListRange || step.Start == nil || *step.Start != query.Start || !equalOptionalUint64(step.End, query.End) {
			return fmt.Errorf("list-range proof does not match query bounds")
		}
	default:
		return fmt.Errorf("%w: unsupported kind %q", ErrInvalidQuery, query.Kind)
	}
	return nil
}

func equalOptionalUint64(a, b *uint64) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// IsQueryNotFound reports whether err represents an unauthenticated or absent
// query target.
func IsQueryNotFound(err error) bool {
	return errors.Is(err, ErrQueryNotFound)
}

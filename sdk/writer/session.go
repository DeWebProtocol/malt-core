package writer

import (
	"context"
	"fmt"
	"sync"

	"github.com/dewebprotocol/malt-core/mutation"
	cid "github.com/ipfs/go-cid"
)

// Session retains verified complete vectors and semantic materialization across
// mutations. Preparing a candidate never advances the session; only an exact
// durable receipt can advance it. Client trust promotion remains a separate
// higher-level policy.
type Session struct {
	mu      sync.Mutex
	runtime *Runtime
	loaded  bool
	current VerifiedUpdateView
}

func NewSession(runtime *Runtime) (*Session, error) {
	if runtime == nil {
		return nil, fmt.Errorf("client writer runtime is nil")
	}
	return &Session{runtime: runtime}, nil
}

// Load verifies and installs the accepted-root update view for this session.
func (s *Session) Load(ctx context.Context, view mutation.UpdateView) error {
	if s == nil {
		return fmt.Errorf("client writer session is nil")
	}
	verified, err := s.runtime.VerifyUpdateView(ctx, view)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.current = verified
	s.loaded = true
	return nil
}

// BaseRoot returns the currently retained accepted base. It is unchanged by
// Prepare and changes only after AcceptReceipt succeeds.
func (s *Session) BaseRoot() cid.Cid {
	if s == nil {
		return cid.Undef
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.loaded {
		return cid.Undef
	}
	return s.current.View.BaseRoot
}

// WorkingRoots returns a detached object-to-root projection of the semantic
// materialization currently used for the next incremental update. During a
// legacy view migration these roots may differ from the roots declared by the
// accepted view, so stateful callers must retain both sets.
func (s *Session) WorkingRoots() map[string]cid.Cid {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.loaded {
		return nil
	}
	roots := make(map[string]cid.Cid, len(s.current.workingRoots))
	for objectID, root := range s.current.workingRoots {
		roots[objectID] = root
	}
	return roots
}

// Prepare computes a candidate against the session's current accepted base.
func (s *Session) Prepare(ctx context.Context, operationID string, intent mutation.SemanticIntent) (ComputeResult, error) {
	if s == nil {
		return ComputeResult{}, fmt.Errorf("client writer session is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.loaded {
		return ComputeResult{}, fmt.Errorf("client writer session has no update view")
	}
	if !intent.BaseRoot.Equals(s.current.View.BaseRoot) {
		return ComputeResult{}, fmt.Errorf("intent base %s is stale; current base is %s", intent.BaseRoot, s.current.View.BaseRoot)
	}
	return s.runtime.ComputeBundle(ctx, operationID, s.current, intent)
}

// AcceptReceipt verifies a service's exact durable acknowledgement and only
// then advances retained writer state to the prepared next view.
func (s *Session) AcceptReceipt(receipt mutation.MaterializationReceipt, prepared ComputeResult) error {
	if s == nil {
		return fmt.Errorf("client writer session is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.loaded {
		return fmt.Errorf("client writer session has no update view")
	}
	current, currentDigest, err := validateVerifiedUpdateView(s.runtime, s.current)
	if err != nil {
		return fmt.Errorf("retained update view: %w", err)
	}
	if prepared.seal.runtime != s.runtime {
		return fmt.Errorf("prepared result does not belong to this client writer runtime")
	}
	bundleDigest, err := prepared.Bundle.Digest()
	if err != nil || bundleDigest != prepared.seal.bundleDigest {
		return fmt.Errorf("prepared client-root bundle seal mismatch")
	}
	next, err := mutation.NormalizeUpdateView(prepared.NextView)
	if err != nil {
		return fmt.Errorf("prepared next view is invalid: %w", err)
	}
	nextDigest, err := next.Digest()
	if err != nil || nextDigest != prepared.seal.nextViewDigest {
		return fmt.Errorf("prepared next-view seal mismatch")
	}
	if !prepared.Bundle.View.BaseRoot.Equals(current.BaseRoot) {
		return fmt.Errorf("prepared bundle base is stale")
	}
	if prepared.Bundle.ViewDigest != currentDigest {
		return fmt.Errorf("prepared bundle update view is stale")
	}
	if err := receipt.Validate(prepared.Bundle); err != nil {
		return err
	}
	if !next.BaseRoot.Equals(prepared.Bundle.Candidate) {
		return fmt.Errorf("prepared next view does not match candidate")
	}
	if len(prepared.seal.workingRoots) != len(next.Objects) {
		return fmt.Errorf("prepared working-root seal does not match next view")
	}
	nextWorkingRoots, err := workingRootsForView(next, prepared.seal.workingRoots)
	if err != nil {
		return fmt.Errorf("prepared working-root seal: %w", err)
	}
	s.current = VerifiedUpdateView{
		View: next, runtime: s.runtime, digest: nextDigest, workingRoots: nextWorkingRoots,
	}
	return nil
}

func validateVerifiedUpdateView(runtime *Runtime, verified VerifiedUpdateView) (mutation.UpdateView, [32]byte, error) {
	if runtime == nil || verified.runtime != runtime {
		return mutation.UpdateView{}, [32]byte{}, fmt.Errorf("verified update view belongs to a different runtime")
	}
	canonical, err := mutation.NormalizeUpdateView(verified.View)
	if err != nil {
		return mutation.UpdateView{}, [32]byte{}, err
	}
	digest, err := canonical.Digest()
	if err != nil {
		return mutation.UpdateView{}, [32]byte{}, err
	}
	if digest != verified.digest {
		return mutation.UpdateView{}, [32]byte{}, fmt.Errorf("verified update view seal mismatch")
	}
	return canonical, digest, nil
}

// Audit recomputes the retained complete vectors. Evaluators use this after a
// long-lived measured session; a failure invalidates the whole run.
func (s *Session) Audit(ctx context.Context) error {
	if s == nil {
		return fmt.Errorf("client writer session is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.loaded {
		return fmt.Errorf("client writer session has no update view")
	}
	verified, err := s.runtime.VerifyUpdateView(ctx, s.current.View)
	if err != nil {
		return err
	}
	s.current = verified
	return nil
}

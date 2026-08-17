// Package verifier provides the client-side MALT verification facade. It is
// deterministic, performs no network or storage I/O, and treats the root,
// operation, query, and optional target in a request as caller-selected input.
package verifier

import (
	"context"
	"fmt"

	malt "github.com/dewebprotocol/malt-core"
	"github.com/dewebprotocol/malt-core/artifact"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
	"github.com/dewebprotocol/malt-core/auth/commitment/kzg"
	"github.com/dewebprotocol/malt-core/auth/proof/prooflist"
	authverifier "github.com/dewebprotocol/malt-core/auth/verifier"
	"github.com/dewebprotocol/malt-core/protocol"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
)

type Verifier struct {
	proofs *authverifier.Verifier
}

// VerifyResolve locally verifies a transport-neutral resolve request/result
// pair. The request is caller-selected; the result and ProofList are untrusted.
func (v *Verifier) VerifyResolve(ctx context.Context, value protocol.ResolveVerification) error {
	if err := value.Validate(); err != nil {
		return err
	}
	if v == nil || v.proofs == nil {
		return fmt.Errorf("client verifier is nil")
	}
	request, _ := value.Request.Core()
	result, _ := value.Result.Core()
	return malt.VerifyResolve(ctx, request, result, v.proofs)
}

// VerifyRead locally verifies one transport-neutral primitive read
// request/result pair.
func (v *Verifier) VerifyRead(ctx context.Context, value protocol.ReadVerification) error {
	if err := value.Validate(); err != nil {
		return err
	}
	if v == nil || v.proofs == nil {
		return fmt.Errorf("client verifier is nil")
	}
	request, _ := value.Request.Core()
	result, _ := value.Result.Core()
	return malt.VerifyRead(ctx, request, result, v.proofs)
}

// VerifyMapProof locally verifies one transport-neutral map membership or
// non-membership request/result pair.
func (v *Verifier) VerifyMapProof(ctx context.Context, value protocol.MapProofVerification) error {
	if err := value.Validate(); err != nil {
		return err
	}
	if v == nil || v.proofs == nil {
		return fmt.Errorf("client verifier is nil")
	}
	request, _ := value.Request.Core()
	result, _ := value.Result.Core()
	return malt.VerifyMapProof(ctx, request, result, v.proofs)
}

func NewDefault() (*Verifier, error) {
	proofs, err := authverifier.NewDefault()
	if err != nil {
		return nil, err
	}
	return &Verifier{proofs: proofs}, nil
}

// NewForBackend creates a portable verifier with only one built-in commitment
// backend. It is intended for clients that isolate backend initialization while
// retaining backend selection from typed roots inside the verifier.
func NewForBackend(kind maltcid.BackendKind) (*Verifier, error) {
	var (
		scheme commitment.IndexVerifier
		err    error
	)
	switch kind {
	case maltcid.BackendKindKZG:
		scheme, err = kzg.NewVerifierScheme()
	case maltcid.BackendKindIPA:
		scheme, err = ipa.NewVerifierScheme()
	default:
		return nil, fmt.Errorf("unsupported verifier backend %q", kind)
	}
	if err != nil {
		return nil, fmt.Errorf("creating %s verifier backend: %w", kind, err)
	}

	registry := authverifier.NewBackendRegistry()
	if err := registry.RegisterScheme(kind, scheme); err != nil {
		return nil, err
	}
	return &Verifier{proofs: authverifier.NewWithRegistry(registry)}, nil
}

// Verify verifies the frozen malt.artifact/v0alpha2 compatibility envelope.
// New callers should use VerifyResolve or VerifyRead.
func (v *Verifier) Verify(ctx context.Context, request Request) error {
	if err := request.Validate(); err != nil {
		return err
	}
	if v == nil || v.proofs == nil {
		return fmt.Errorf("client verifier is nil")
	}
	return artifact.Verify(ctx, artifact.VerifyRequest{Profile: artifact.Profile, Artifact: request.Artifact}, v.proofs)
}

// VerifyProofList verifies bare evidence locally. Prefer VerifyResolve or
// VerifyRead so caller-selected inputs are bound to the untrusted result.
func (v *Verifier) VerifyProofList(ctx context.Context, value prooflist.ProofList) (bool, error) {
	if v == nil || v.proofs == nil {
		return false, fmt.Errorf("client verifier is nil")
	}
	return v.proofs.VerifyProofList(ctx, value)
}

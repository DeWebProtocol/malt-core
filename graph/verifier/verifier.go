// Package verifier preserves the graph-runtime verifier constructor while
// delegating proof checks to the portable authentication kernel.
package verifier

import (
	"context"
	"fmt"

	"github.com/dewebprotocol/malt-core/auth/proof/prooflist"
	"github.com/dewebprotocol/malt-core/auth/semantic/list"
	"github.com/dewebprotocol/malt-core/auth/semantic/mapping"
	authverifier "github.com/dewebprotocol/malt-core/auth/verifier"
)

// Runtime is the minimal reference-runtime surface needed to construct the
// compatibility adapter. Verification itself is owned by auth/verifier and
// does not consume resolver, ArcTable, CAS, server, or daemon state.
type Runtime interface {
	Semantic() mapping.Semantics
	ListSemantic() list.Semantics
}

// Verifier adapts runtime semantic implementations to the portable verifier.
type Verifier struct {
	inner *authverifier.Verifier
}

// New creates a compatibility verifier over runtime's verification methods.
func New(runtime Runtime) *Verifier {
	if runtime == nil {
		return &Verifier{}
	}
	return &Verifier{inner: authverifier.New(runtime.Semantic(), runtime.ListSemantic())}
}

// VerifyProofList delegates complete ordered, query-bound, cryptographic
// verification to auth/verifier.
func (v *Verifier) VerifyProofList(ctx context.Context, pl prooflist.ProofList) (bool, error) {
	if v == nil || v.inner == nil {
		return false, fmt.Errorf("verifier runtime is nil")
	}
	return v.inner.VerifyProofList(ctx, pl)
}

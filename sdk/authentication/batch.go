package authentication

import (
	"context"
	"fmt"

	"github.com/dewebprotocol/malt-core/engine"
	"github.com/dewebprotocol/malt-core/protocol"
)

// ValidateBatch verifies every candidate before a caller starts durable writes.
// It does not prove a relation between Base and Root, verify application intent,
// or promote a candidate to a trusted Root. Durable atomicity is caller-owned.
func ValidateBatch(ctx context.Context, e *engine.Engine, batch protocol.AuthenticationBatch) error {
	if err := batch.Validate(); err != nil {
		return err
	}
	for i, candidate := range batch.Candidates {
		if err := ValidateCandidate(ctx, e, candidate); err != nil {
			return fmt.Errorf("candidate %d: %w", i, err)
		}
	}
	return nil
}

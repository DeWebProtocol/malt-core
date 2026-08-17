//go:build !malt_no_default_kzg

package runtimegraph

import (
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/commitment/kzg"
)

func newDefaultCommitmentScheme() (commitment.IndexCommitment, error) {
	return kzg.NewScheme()
}

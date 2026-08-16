//go:build malt_no_default_kzg

package runtimegraph

import (
	"fmt"

	"github.com/dewebprotocol/malt-core/auth/commitment"
)

func newDefaultCommitmentScheme() (commitment.IndexCommitment, error) {
	return nil, fmt.Errorf("default KZG scheme is excluded; inject an explicit commitment backend")
}

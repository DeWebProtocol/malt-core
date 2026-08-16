package resolver

import (
	"github.com/dewebprotocol/malt-core/auth/arcset"
	"github.com/dewebprotocol/malt-core/auth/proof/evidence"
	cid "github.com/ipfs/go-cid"
)

// Transcript records the evidence for each resolution step.
type Transcript struct {
	Steps []StepEvidence
}

// StepEvidence represents evidence for a single resolution step.
type StepEvidence struct {
	// Path is the path segment consumed in this step.
	Path arcset.Path

	// Target is the CID resolved to in this step.
	Target cid.Cid

	// Evidence is the cryptographic evidence for this step.
	Evidence evidence.Evidence
}

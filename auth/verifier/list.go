// Package verifier contains verifier-critical helpers for ProofList evidence.
package verifier

import (
	"fmt"

	"github.com/dewebprotocol/malt-core/auth/proof/prooflist"
	structure "github.com/dewebprotocol/malt-core/auth/semantic"
	"github.com/dewebprotocol/malt-core/auth/semantic/list"
	cid "github.com/ipfs/go-cid"
)

// VerifyProofListListStructure verifies list-backed ProofList structure steps
// through the supplied verification-only list backend.
func VerifyProofListListStructure(lists ListVerifier, step prooflist.Step, stepIndex int) (bool, error) {
	if lists == nil {
		return false, fmt.Errorf("prooflist step %d list verifier is nil", stepIndex)
	}
	switch step.EvidenceBackend {
	case "list":
		if step.Index == nil {
			return false, fmt.Errorf("prooflist step %d list index is missing", stepIndex)
		}
		if step.Length == nil {
			return false, fmt.Errorf("prooflist step %d list length is missing", stepIndex)
		}
		return lists.Verify(step.From, *step.Index, list.Query{Key: step.Target, Length: *step.Length}, structure.Proof(step.Proof))
	case "measured_list":
		if !step.Target.Equals(step.From) {
			return false, nil
		}
		if step.Start == nil {
			return false, fmt.Errorf("prooflist step %d list range start is missing", stepIndex)
		}
		if step.ChildCount == nil {
			return false, fmt.Errorf("prooflist step %d list range child count is missing", stepIndex)
		}
		if step.TotalSize == nil {
			return false, fmt.Errorf("prooflist step %d list range total size is missing", stepIndex)
		}
		if step.ChunkSize == nil {
			return false, fmt.Errorf("prooflist step %d list range chunk size is missing", stepIndex)
		}
		measured, ok := lists.(MeasuredListVerifier)
		if !ok {
			return false, fmt.Errorf("prooflist step %d has measured list evidence but graph list semantic does not support measured ranges", stepIndex)
		}
		return measured.VerifyRange(step.From, *step.Start, step.End, list.RangeResult{
			Metadata: list.RangeMetadata{
				ChildCount: *step.ChildCount,
				TotalSize:  *step.TotalSize,
				ChunkSize:  *step.ChunkSize,
			},
			Segments: append([]cid.Cid(nil), step.Segments...),
		}, structure.Proof(step.Proof))
	default:
		return false, fmt.Errorf("prooflist step %d has unsupported structure evidence backend %q", stepIndex, step.EvidenceBackend)
	}
}

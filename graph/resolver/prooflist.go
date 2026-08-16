package resolver

import (
	"fmt"

	"github.com/dewebprotocol/malt-core/auth/proof/evidence"
	"github.com/dewebprotocol/malt-core/auth/proof/prooflist"
	cid "github.com/ipfs/go-cid"
)

// ProofListFromTranscript converts the current resolver transcript into the
// verifier-facing ProofList schema. It preserves transcript order and evidence
// bytes; it does not perform cryptographic verification.
func ProofListFromTranscript(root cid.Cid, transcript *Transcript) (*prooflist.ProofList, error) {
	if !root.Defined() {
		return nil, fmt.Errorf("root is undefined")
	}
	if transcript == nil {
		return nil, fmt.Errorf("transcript is nil")
	}

	pl := &prooflist.ProofList{
		Root:  root,
		Steps: make([]prooflist.Step, 0, len(transcript.Steps)),
	}
	from := root
	for _, transcriptStep := range transcript.Steps {
		step := prooflist.Step{
			Kind:         transcriptStepKind(transcriptStep),
			From:         from,
			Path:         transcriptStep.Path.String(),
			Query:        transcriptStep.Path.String(),
			Target:       transcriptStep.Target,
			EvidenceKind: evidenceKindLabel(transcriptStep.Evidence),
			Evidence:     cloneEvidenceBytes(transcriptStep.Evidence),
		}
		pl.Steps = append(pl.Steps, step)
		from = transcriptStep.Target
	}
	return pl, nil
}

func transcriptStepKind(step StepEvidence) prooflist.StepKind {
	if step.Path.String() == "@payload" {
		return prooflist.KindPayloadBinding
	}
	if step.Evidence != nil && step.Evidence.Kind() == evidence.EvidenceKindImplicit {
		return prooflist.KindImplicitBlock
	}
	return prooflist.KindMapStep
}

func evidenceKindLabel(ev evidence.Evidence) string {
	if ev == nil {
		return ""
	}
	switch ev.Kind() {
	case evidence.EvidenceKindExplicit:
		return "explicit"
	case evidence.EvidenceKindImplicit:
		return "implicit"
	case evidence.EvidenceKindHAMT:
		return "hamt"
	default:
		return "unknown"
	}
}

func cloneEvidenceBytes(ev evidence.Evidence) []byte {
	if ev == nil {
		return nil
	}
	bytes := ev.Bytes()
	out := make([]byte, len(bytes))
	copy(out, bytes)
	return out
}

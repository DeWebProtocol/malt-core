// Package prooflist defines the verifier-facing read proof transcript shape.
package prooflist

import (
	"fmt"

	cid "github.com/ipfs/go-cid"
)

// StepKind identifies the semantic role of one ordered proof step.
type StepKind string

const (
	KindMapStep        StepKind = "map_step"
	KindMapAbsence     StepKind = "map_absence"
	KindPayloadBinding StepKind = "payload_binding"
	KindListIndex      StepKind = "list_index"
	KindListRange      StepKind = "list_range"
)

// ProofList is an ordered verifier-facing proof artifact for a read.
//
// It is a schema and adapter boundary only. Cryptographic verification is still
// owned by the concrete semantic backend that emitted each proof payload.
type ProofList struct {
	Root  cid.Cid `json:"root"`
	Query string  `json:"query,omitempty"`
	Steps []Step  `json:"steps"`
}

// Step records one hop from a structure root or block to a target CID.
type Step struct {
	Kind            StepKind  `json:"kind"`
	From            cid.Cid   `json:"from"`
	Query           string    `json:"query,omitempty"`
	Coordinate      string    `json:"coordinate,omitempty"`
	Path            string    `json:"path,omitempty"`
	Index           *uint64   `json:"index,omitempty"`
	Length          *uint64   `json:"length,omitempty"`
	Start           *uint64   `json:"start,omitempty"`
	End             *uint64   `json:"end,omitempty"`
	ChildCount      *uint64   `json:"child_count,omitempty"`
	TotalSize       *uint64   `json:"total_size,omitempty"`
	ChunkSize       *uint64   `json:"chunk_size,omitempty"`
	Target          cid.Cid   `json:"target"`
	Segments        []cid.Cid `json:"segments,omitempty"`
	EvidenceKind    string    `json:"evidence_kind,omitempty"`
	EvidenceBackend string    `json:"evidence_backend,omitempty"`
	Evidence        []byte    `json:"evidence,omitempty"`
	Proof           []byte    `json:"proof,omitempty"`
}

type validateConfig struct {
	requireSteps bool
}

// ValidateOption customizes shape validation.
type ValidateOption func(*validateConfig)

// RequireSteps rejects a ProofList with no ordered steps.
func RequireSteps() ValidateOption {
	return func(cfg *validateConfig) {
		cfg.requireSteps = true
	}
}

// ValidateShape checks that the ProofList is structurally usable by a verifier.
//
// This does not perform cryptographic end-to-end verification.
func (p ProofList) ValidateShape(opts ...ValidateOption) error {
	cfg := validateConfig{}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	if !p.Root.Defined() {
		return fmt.Errorf("prooflist root is undefined")
	}
	if cfg.requireSteps && len(p.Steps) == 0 {
		return fmt.Errorf("prooflist steps are empty")
	}
	current := p.Root
	listIndexPhase := false
	for i, step := range p.Steps {
		if !step.Kind.Known() {
			return fmt.Errorf("prooflist step %d has unknown kind %q", i, step.Kind)
		}
		if !step.From.Defined() {
			return fmt.Errorf("prooflist step %d from CID is undefined", i)
		}
		terminalAbsence := step.Kind == KindMapAbsence && i == len(p.Steps)-1
		if step.Kind == KindMapAbsence && !terminalAbsence {
			return fmt.Errorf("prooflist step %d map_absence must be terminal", i)
		}
		if !step.Target.Defined() && !terminalAbsence {
			return fmt.Errorf("prooflist step %d target CID is undefined", i)
		}
		if terminalAbsence && step.Target.Defined() {
			return fmt.Errorf("prooflist step %d map_absence target CID must be undefined", i)
		}
		if !step.From.Equals(current) {
			return fmt.Errorf("prooflist step %d from CID %s does not continue from current target %s", i, step.From.String(), current.String())
		}
		listIndexEvidence := step.structureListEvidence()
		listRangeEvidence := step.structureMeasuredListEvidence()
		if step.Kind == KindListIndex && !listIndexEvidence {
			return fmt.Errorf("prooflist step %d list_index kind does not match evidence labels %q/%q", i, step.EvidenceKind, step.EvidenceBackend)
		}
		if step.Kind == KindListRange && !listRangeEvidence {
			return fmt.Errorf("prooflist step %d list_range kind does not match evidence labels %q/%q", i, step.EvidenceKind, step.EvidenceBackend)
		}
		if listIndexEvidence && step.Kind != KindListIndex {
			return fmt.Errorf("prooflist step %d structure/list evidence does not match kind %q", i, step.Kind)
		}
		if listRangeEvidence && step.Kind != KindListRange {
			return fmt.Errorf("prooflist step %d structure/measured_list evidence does not match kind %q", i, step.Kind)
		}
		if listIndexEvidence || listRangeEvidence {
			listIndexPhase = true
			continue
		}
		if terminalAbsence {
			if step.EvidenceKind != "structure" || step.EvidenceBackend != "map" {
				return fmt.Errorf("prooflist step %d map_absence kind does not match structure/map evidence", i)
			}
			continue
		}
		if listIndexPhase {
			return fmt.Errorf("prooflist step %d traversal step appears after list index evidence", i)
		}
		current = step.Target
	}
	return nil
}

// LastStepTarget returns the target CID of the final ordered step.
func (p ProofList) LastStepTarget() (cid.Cid, error) {
	if err := p.ValidateShape(RequireSteps()); err != nil {
		return cid.Undef, err
	}
	return p.Steps[len(p.Steps)-1].Target, nil
}

// Known reports whether k is part of the current ProofList schema.
func (k StepKind) Known() bool {
	switch k {
	case KindMapStep, KindMapAbsence, KindPayloadBinding, KindListIndex, KindListRange:
		return true
	default:
		return false
	}
}

func (s Step) structureListEvidence() bool {
	return s.EvidenceKind == "structure" && s.EvidenceBackend == "list"
}

func (s Step) structureMeasuredListEvidence() bool {
	return s.EvidenceKind == "structure" && s.EvidenceBackend == "measured_list"
}

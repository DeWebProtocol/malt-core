package protocol

import (
	"encoding/json"
	"fmt"

	"github.com/dewebprotocol/malt-core/mutation"
)

const (
	WriterComputeResultProfileV1 = "malt.writer-compute-result/v1"
	WriterComputeResultProfile   = "malt.writer-compute-result/v2"
)

// WriterComputeMetrics reports browser-local writer phases. These values are
// diagnostic timing data, not authenticated protocol evidence.
type WriterComputeMetrics struct {
	ViewNormalizationNS    uint64 `json:"view_normalization_ns"`
	IntentNormalizationNS  uint64 `json:"intent_normalization_ns"`
	DigestNS               uint64 `json:"digest_ns"`
	CommitmentUpdateNS     uint64 `json:"commitment_update_ns"`
	RootComputationNS      uint64 `json:"root_computation_ns"`
	ExpectedRootEncodingNS uint64 `json:"expected_root_encoding_ns"`
	BundleValidationNS     uint64 `json:"bundle_validation_ns"`
	NextViewNS             uint64 `json:"next_view_ns"`
	TotalNS                uint64 `json:"total_ns"`
}

// WriterComputeResult is the versioned browser wire result for one exact
// client-root computation.
type WriterComputeResult struct {
	Profile         string                    `json:"profile"`
	Materialization ClientRootMaterialization `json:"materialization"`
	Bundle          ClientRootBundle          `json:"bundle"`
	NextView        UpdateView                `json:"next_view"`
	Metrics         WriterComputeMetrics      `json:"metrics"`
}

type writerComputeResultV1 struct {
	Profile  string               `json:"profile"`
	Bundle   ClientRootBundle     `json:"bundle"`
	NextView UpdateView           `json:"next_view"`
	Metrics  WriterComputeMetrics `json:"metrics"`
}

// MarshalJSON preserves the selected wire profile. In particular, a decoded
// v1 value must not acquire the v2-only materialization member when relayed.
func (r WriterComputeResult) MarshalJSON() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	if r.Profile == WriterComputeResultProfileV1 {
		return json.Marshal(writerComputeResultV1{
			Profile: r.Profile, Bundle: r.Bundle, NextView: r.NextView, Metrics: r.Metrics,
		})
	}
	type writerComputeResultV2 WriterComputeResult
	return json.Marshal(writerComputeResultV2(r))
}

// NewWriterComputeResult projects canonical core values into the browser wire
// result and checks the candidate-to-next-view binding.
func NewWriterComputeResult(bundle mutation.ClientRootBundle, materialization mutation.ClientRootMaterialization, nextView mutation.UpdateView, metrics WriterComputeMetrics) (WriterComputeResult, error) {
	wireBundle, err := NewClientRootBundle(bundle)
	if err != nil {
		return WriterComputeResult{}, fmt.Errorf("encode writer bundle: %w", err)
	}
	wireMaterialization, err := NewClientRootMaterialization(bundle, materialization)
	if err != nil {
		return WriterComputeResult{}, fmt.Errorf("encode writer materialization: %w", err)
	}
	wireNextView, err := NewUpdateView(nextView)
	if err != nil {
		return WriterComputeResult{}, fmt.Errorf("encode writer next view: %w", err)
	}
	result := WriterComputeResult{
		Profile:         WriterComputeResultProfile,
		Bundle:          wireBundle,
		Materialization: wireMaterialization,
		NextView:        wireNextView,
		Metrics:         metrics,
	}
	if err := result.Validate(); err != nil {
		return WriterComputeResult{}, err
	}
	return result, nil
}

// Validate checks the complete nested wire values and requires the retained
// next view to start at the exact bundle candidate.
func (r WriterComputeResult) Validate() error {
	if r.Profile != WriterComputeResultProfile && r.Profile != WriterComputeResultProfileV1 {
		return fmt.Errorf("unsupported writer compute result profile %q", r.Profile)
	}
	bundle, err := r.Bundle.Core()
	if err != nil {
		return fmt.Errorf("writer compute result bundle: %w", err)
	}
	if r.Profile == WriterComputeResultProfile {
		if _, err := r.Materialization.Core(bundle); err != nil {
			return fmt.Errorf("writer compute result materialization: %w", err)
		}
	} else if r.Materialization.Profile != "" || r.Materialization.Base != nil || len(r.Materialization.Maps) != 0 {
		return fmt.Errorf("writer compute result v1 must not carry materialization")
	}
	nextView, err := r.NextView.Core()
	if err != nil {
		return fmt.Errorf("writer compute result next view: %w", err)
	}
	if !nextView.BaseRoot.Equals(bundle.Candidate) {
		return fmt.Errorf("writer next-view base %s does not match candidate %s", nextView.BaseRoot, bundle.Candidate)
	}
	return nil
}

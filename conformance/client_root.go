package conformance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/dewebprotocol/malt-core/protocol"
)

const ClientRootV1 = "malt.client-root.conformance/v1"

//go:generate go run ../internal/conformancegen/cmd -corpus client-root -out client-root/v1/vectors.json

// ClientRootCorpus freezes complete-view inputs and exact candidate outputs
// without treating a candidate or receipt as a portable transition proof.
type ClientRootCorpus struct {
	SchemaVersion string             `json:"schema_version"`
	Vectors       []ClientRootVector `json:"vectors"`
}

type ClientRootVector struct {
	ID             string             `json:"id"`
	Backend        string             `json:"backend"`
	Category       string             `json:"category"`
	OperationID    string             `json:"operation_id"`
	UpdateView     json.RawMessage    `json:"update_view"`
	SemanticIntent json.RawMessage    `json:"semantic_intent"`
	Expected       ClientRootExpected `json:"expected"`
}

type ClientRootExpected struct {
	Valid           bool                                `json:"valid"`
	Bundle          *protocol.ClientRootBundle          `json:"bundle,omitempty"`
	Materialization *protocol.ClientRootMaterialization `json:"materialization,omitempty"`
	NextView        *protocol.UpdateView                `json:"next_view,omitempty"`
	Receipt         *protocol.MaterializationReceipt    `json:"receipt,omitempty"`
}

func (e *ClientRootExpected) UnmarshalJSON(data []byte) error {
	type expectedWire struct {
		Valid           *bool                               `json:"valid"`
		Bundle          *protocol.ClientRootBundle          `json:"bundle,omitempty"`
		Materialization *protocol.ClientRootMaterialization `json:"materialization,omitempty"`
		NextView        *protocol.UpdateView                `json:"next_view,omitempty"`
		Receipt         *protocol.MaterializationReceipt    `json:"receipt,omitempty"`
	}
	var wire expectedWire
	if err := decodeStrict(data, &wire); err != nil {
		return err
	}
	if wire.Valid == nil {
		return fmt.Errorf("expected.valid is required")
	}
	*e = ClientRootExpected{
		Valid: *wire.Valid, Bundle: wire.Bundle, Materialization: wire.Materialization,
		NextView: wire.NextView, Receipt: wire.Receipt,
	}
	return nil
}

func LoadClientRoot() (ClientRootCorpus, error) {
	data, err := ClientRootBytes()
	if err != nil {
		return ClientRootCorpus{}, err
	}
	var corpus ClientRootCorpus
	if err := decodeStrict(data, &corpus); err != nil {
		return ClientRootCorpus{}, fmt.Errorf("decode client-root conformance corpus: %w", err)
	}
	if err := corpus.Validate(); err != nil {
		return ClientRootCorpus{}, err
	}
	return corpus, nil
}

func ClientRootBytes() ([]byte, error) {
	data, err := corpusFiles.ReadFile("client-root/v1/vectors.json")
	if err != nil {
		return nil, fmt.Errorf("read embedded client-root conformance corpus: %w", err)
	}
	return slices.Clone(data), nil
}

func ClientRootSchema(name string) ([]byte, error) {
	if name != "corpus.schema.json" && name != "vector.schema.json" {
		return nil, fmt.Errorf("unknown client-root conformance schema %q", name)
	}
	data, err := corpusFiles.ReadFile("client-root/v1/" + name)
	if err != nil {
		return nil, fmt.Errorf("read client-root conformance schema %q: %w", name, err)
	}
	return slices.Clone(data), nil
}

func (c ClientRootCorpus) Validate() error {
	if c.SchemaVersion != ClientRootV1 {
		return fmt.Errorf("unsupported client-root conformance schema version %q", c.SchemaVersion)
	}
	if len(c.Vectors) == 0 {
		return fmt.Errorf("client-root conformance corpus has no vectors")
	}
	seen := make(map[string]struct{}, len(c.Vectors))
	for index, vector := range c.Vectors {
		if err := vector.Validate(); err != nil {
			return fmt.Errorf("client-root vector %d: %w", index, err)
		}
		if _, exists := seen[vector.ID]; exists {
			return fmt.Errorf("duplicate client-root conformance vector id %q", vector.ID)
		}
		seen[vector.ID] = struct{}{}
	}
	return nil
}

func (v ClientRootVector) Validate() error {
	if !validVectorID(v.ID) {
		return fmt.Errorf("invalid client-root vector id %q", v.ID)
	}
	if v.Backend != BackendKZG && v.Backend != BackendIPA {
		return fmt.Errorf("vector %q has unsupported backend %q", v.ID, v.Backend)
	}
	if v.Category == "" {
		return fmt.Errorf("vector %q has empty category", v.ID)
	}
	if v.OperationID == "" || strings.TrimSpace(v.OperationID) != v.OperationID {
		return fmt.Errorf("vector %q has invalid operation_id", v.ID)
	}
	for name, raw := range map[string]json.RawMessage{"update_view": v.UpdateView, "semantic_intent": v.SemanticIntent} {
		trimmed := bytes.TrimSpace(raw)
		if len(trimmed) == 0 || trimmed[0] != '{' || !json.Valid(trimmed) {
			return fmt.Errorf("vector %q %s is not a JSON object", v.ID, name)
		}
	}
	outputsPresent := v.Expected.Bundle != nil || v.Expected.Materialization != nil || v.Expected.NextView != nil || v.Expected.Receipt != nil
	if !v.Expected.Valid {
		if outputsPresent {
			return fmt.Errorf("invalid vector %q carries expected outputs", v.ID)
		}
		return nil
	}
	if v.Expected.Bundle == nil || v.Expected.Materialization == nil || v.Expected.NextView == nil || v.Expected.Receipt == nil {
		return fmt.Errorf("valid vector %q is missing expected outputs", v.ID)
	}
	bundle, err := v.Expected.Bundle.Core()
	if err != nil {
		return fmt.Errorf("valid vector %q bundle: %w", v.ID, err)
	}
	if _, err := v.Expected.Materialization.Core(bundle); err != nil {
		return fmt.Errorf("valid vector %q materialization: %w", v.ID, err)
	}
	nextView, err := v.Expected.NextView.Core()
	if err != nil {
		return fmt.Errorf("valid vector %q next view: %w", v.ID, err)
	}
	if !nextView.BaseRoot.Equals(bundle.Candidate) {
		return fmt.Errorf("valid vector %q next view does not start at its candidate", v.ID)
	}
	if _, err := v.Expected.Receipt.Core(bundle); err != nil {
		return fmt.Errorf("valid vector %q receipt: %w", v.ID, err)
	}
	return nil
}

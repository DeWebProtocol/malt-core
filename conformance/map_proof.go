package conformance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/dewebprotocol/malt-core/protocol"
)

const (
	MapProofV1        = "malt.map-proof.conformance/v1"
	OperationMapProof = "map_proof"
)

//go:generate go run ../internal/conformancegen/cmd -corpus map-proof -out map-proof/v1/vectors.json

// MapProofCorpus is the frozen language-neutral membership/non-membership
// verification corpus.
type MapProofCorpus struct {
	SchemaVersion string           `json:"schema_version"`
	Vectors       []MapProofVector `json:"vectors"`
}

type MapProofVector struct {
	ID           string          `json:"id"`
	Operation    string          `json:"operation"`
	Backend      string          `json:"backend"`
	Category     string          `json:"category"`
	Verification json.RawMessage `json:"verification"`
	Expected     Expected        `json:"expected"`
}

type MapProofVerifier interface {
	VerifyMapProof(context.Context, protocol.MapProofVerification) error
}

func LoadMapProof() (MapProofCorpus, error) {
	data, err := MapProofBytes()
	if err != nil {
		return MapProofCorpus{}, err
	}
	var corpus MapProofCorpus
	if err := decodeStrict(data, &corpus); err != nil {
		return MapProofCorpus{}, fmt.Errorf("decode Map-proof conformance corpus: %w", err)
	}
	if err := corpus.Validate(); err != nil {
		return MapProofCorpus{}, err
	}
	return corpus, nil
}

func MapProofBytes() ([]byte, error) {
	data, err := corpusFiles.ReadFile("map-proof/v1/vectors.json")
	if err != nil {
		return nil, fmt.Errorf("read embedded Map-proof conformance corpus: %w", err)
	}
	return slices.Clone(data), nil
}

func MapProofSchema(name string) ([]byte, error) {
	if name != "corpus.schema.json" && name != "vector.schema.json" {
		return nil, fmt.Errorf("unknown Map-proof conformance schema %q", name)
	}
	data, err := corpusFiles.ReadFile("map-proof/v1/" + name)
	if err != nil {
		return nil, fmt.Errorf("read Map-proof conformance schema %q: %w", name, err)
	}
	return slices.Clone(data), nil
}

func (c MapProofCorpus) Validate() error {
	if c.SchemaVersion != MapProofV1 {
		return fmt.Errorf("unsupported Map-proof conformance schema version %q", c.SchemaVersion)
	}
	if len(c.Vectors) == 0 {
		return fmt.Errorf("Map-proof conformance corpus has no vectors")
	}
	seen := make(map[string]struct{}, len(c.Vectors))
	for index, vector := range c.Vectors {
		if err := vector.Validate(); err != nil {
			return fmt.Errorf("Map-proof vector %d: %w", index, err)
		}
		if _, exists := seen[vector.ID]; exists {
			return fmt.Errorf("duplicate Map-proof conformance vector id %q", vector.ID)
		}
		seen[vector.ID] = struct{}{}
	}
	return nil
}

func (v MapProofVector) Validate() error {
	if !validVectorID(v.ID) {
		return fmt.Errorf("invalid Map-proof vector id %q", v.ID)
	}
	if v.Operation != OperationMapProof {
		return fmt.Errorf("vector %q has unsupported operation %q", v.ID, v.Operation)
	}
	if v.Backend != BackendKZG && v.Backend != BackendIPA {
		return fmt.Errorf("vector %q has unsupported backend %q", v.ID, v.Backend)
	}
	if v.Category == "" {
		return fmt.Errorf("vector %q has empty category", v.ID)
	}
	trimmed := bytes.TrimSpace(v.Verification)
	if len(trimmed) == 0 || trimmed[0] != '{' || !json.Valid(trimmed) {
		return fmt.Errorf("vector %q verification is not a JSON object", v.ID)
	}
	return nil
}

func AcceptedMapProof(ctx context.Context, verifier MapProofVerifier, vector MapProofVector) bool {
	if verifier == nil {
		return false
	}
	value, err := protocol.DecodeMapProofVerification(vector.Verification)
	return err == nil && verifier.VerifyMapProof(ctx, value) == nil
}

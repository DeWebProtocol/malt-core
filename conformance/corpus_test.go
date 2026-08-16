package conformance_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/dewebprotocol/malt-core/conformance"
	"github.com/dewebprotocol/malt-core/internal/conformancegen"
	"github.com/dewebprotocol/malt-core/protocol"
	sdkverifier "github.com/dewebprotocol/malt-core/sdk/verifier"
)

func TestResolveReadCorpora(t *testing.T) {
	for _, version := range []string{conformance.ResolveReadV1, conformance.ResolveReadV2} {
		t.Run(version, func(t *testing.T) {
			corpus, err := conformance.LoadVersion(version)
			if err != nil {
				t.Fatalf("LoadVersion: %v", err)
			}
			verifier, err := sdkverifier.NewDefault()
			if err != nil {
				t.Fatalf("NewDefault: %v", err)
			}
			for _, vector := range corpus.Vectors {
				vector := vector
				t.Run(vector.ID, func(t *testing.T) {
					accepted := conformance.Accepted(context.Background(), verifier, vector)
					if accepted != vector.Expected.Valid {
						t.Fatalf("accepted = %t, want %t", accepted, vector.Expected.Valid)
					}
				})
			}
		})
	}
}

func TestResolveReadV2CorpusIsGenerated(t *testing.T) {
	want, err := conformance.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	got, err := conformancegen.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("checked-in vectors.json is stale; run go generate ./conformance")
	}
}

func TestResolveReadSchemasAreJSON(t *testing.T) {
	for _, version := range []string{conformance.ResolveReadV1, conformance.ResolveReadV2} {
		for _, name := range []string{"corpus.schema.json", "vector.schema.json"} {
			data, err := conformance.SchemaVersion(version, name)
			if err != nil {
				t.Fatalf("SchemaVersion(%q, %q): %v", version, name, err)
			}
			if !json.Valid(data) {
				t.Fatalf("SchemaVersion(%q, %q) is not valid JSON", version, name)
			}
		}
	}
}

func TestResolveReadV1CorpusDigestIsImmutable(t *testing.T) {
	data, err := conformance.BytesVersion(conformance.ResolveReadV1)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != "8fadfc423acdcb78b0c0db520c7320bb72f995e6e5e0dd9da63a41a6c6603e36" {
		t.Fatalf("v1 corpus digest changed: %s", got)
	}
}

func TestResolveReadV2CorpusDigestIsImmutable(t *testing.T) {
	data, err := conformance.BytesVersion(conformance.ResolveReadV2)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != "f96aad71c4b60a3073f823bb2aa0b05307f18400630e1920ad25889beb4600d5" {
		t.Fatalf("v2 corpus digest changed: %s", got)
	}
}

func TestResolveReadV2CoverageMatrix(t *testing.T) {
	corpus, err := conformance.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	type coverageKey struct {
		operation string
		backend   string
		category  string
		valid     bool
	}
	covered := make(map[coverageKey]bool, len(corpus.Vectors))
	for _, vector := range corpus.Vectors {
		covered[coverageKey{vector.Operation, vector.Backend, vector.Category, vector.Expected.Valid}] = true
	}

	required := []coverageKey{{conformance.OperationResolve, conformance.BackendNone, "identity", true}}
	for _, backend := range []string{conformance.BackendKZG, conformance.BackendIPA} {
		required = append(required,
			coverageKey{conformance.OperationResolve, backend, "map_key", true},
			coverageKey{conformance.OperationResolve, backend, "multihop", true},
			coverageKey{conformance.OperationResolve, backend, "payload", true},
			coverageKey{conformance.OperationRead, backend, "map_key", true},
			coverageKey{conformance.OperationRead, backend, "payload", true},
			coverageKey{conformance.OperationRead, backend, "list_index", true},
			coverageKey{conformance.OperationRead, backend, "list_range", true},
			coverageKey{conformance.OperationResolve, backend, "tamper", false},
			coverageKey{conformance.OperationResolve, backend, "cross_root", false},
			coverageKey{conformance.OperationResolve, backend, "malformed_evidence", false},
			coverageKey{conformance.OperationResolve, backend, "strict_json", false},
			coverageKey{conformance.OperationRead, backend, "tamper", false},
			coverageKey{conformance.OperationRead, backend, "cross_root", false},
			coverageKey{conformance.OperationRead, backend, "cross_kind", false},
			coverageKey{conformance.OperationRead, backend, "cross_backend", false},
			coverageKey{conformance.OperationRead, backend, "malformed_evidence", false},
			coverageKey{conformance.OperationRead, backend, "strict_json", false},
		)
	}
	for _, key := range required {
		if !covered[key] {
			t.Errorf("missing coverage: operation=%s backend=%s category=%s valid=%t", key.operation, key.backend, key.category, key.valid)
		}
	}
}

func TestResolveReadV2CryptographicTamperInputsRemainDecodable(t *testing.T) {
	corpus, err := conformance.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, vector := range corpus.Vectors {
		if !strings.Contains(vector.ID, ".proof-tamper.") && !strings.Contains(vector.ID, ".evidence-tamper.") {
			continue
		}
		vector := vector
		t.Run(vector.ID, func(t *testing.T) {
			var semanticProof []byte
			switch vector.Operation {
			case conformance.OperationResolve:
				value, err := protocol.DecodeResolveVerification(vector.Verification)
				if err != nil {
					t.Fatalf("strict DTO decode: %v", err)
				}
				semanticProof = value.Result.ProofList.Steps[0].Evidence
			case conformance.OperationRead:
				value, err := protocol.DecodeReadVerification(vector.Verification)
				if err != nil {
					t.Fatalf("strict DTO decode: %v", err)
				}
				semanticProof = value.Result.ProofList.Steps[0].Proof
			default:
				t.Fatalf("unexpected operation %q", vector.Operation)
			}
			if err := validateSemanticProofEnvelope(semanticProof); err != nil {
				t.Fatalf("semantic proof envelope: %v", err)
			}
		})
	}
}

func validateSemanticProofEnvelope(raw []byte) error {
	var envelope struct {
		Steps []struct {
			Proof string `json:"proof"`
		} `json:"steps"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return err
	}
	if len(envelope.Steps) == 0 {
		return fmt.Errorf("steps are empty")
	}
	proof, err := base64.StdEncoding.DecodeString(envelope.Steps[0].Proof)
	if err != nil {
		return err
	}
	if len(proof) < 4 {
		return fmt.Errorf("primitive proof is too short")
	}
	return nil
}

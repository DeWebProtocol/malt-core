package conformance_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/dewebprotocol/malt-core/conformance"
	"github.com/dewebprotocol/malt-core/internal/conformancegen"
	sdkverifier "github.com/dewebprotocol/malt-core/sdk/verifier"
)

func TestMapProofCorpus(t *testing.T) {
	corpus, err := conformance.LoadMapProof()
	if err != nil {
		t.Fatalf("LoadMapProof: %v", err)
	}
	verifier, err := sdkverifier.NewDefault()
	if err != nil {
		t.Fatalf("NewDefault: %v", err)
	}
	for _, vector := range corpus.Vectors {
		vector := vector
		t.Run(vector.ID, func(t *testing.T) {
			accepted := conformance.AcceptedMapProof(context.Background(), verifier, vector)
			if accepted != vector.Expected.Valid {
				t.Fatalf("accepted = %t, want %t", accepted, vector.Expected.Valid)
			}
		})
	}
}

func TestMapProofCorpusIsGenerated(t *testing.T) {
	want, err := conformance.MapProofBytes()
	if err != nil {
		t.Fatalf("MapProofBytes: %v", err)
	}
	got, err := conformancegen.GenerateMapProof()
	if err != nil {
		t.Fatalf("GenerateMapProof: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("checked-in Map-proof vectors.json is stale; run go generate ./conformance")
	}
}

func TestMapProofSchemasAreJSON(t *testing.T) {
	for _, name := range []string{"corpus.schema.json", "vector.schema.json"} {
		data, err := conformance.MapProofSchema(name)
		if err != nil {
			t.Fatalf("MapProofSchema(%q): %v", name, err)
		}
		if !json.Valid(data) {
			t.Fatalf("MapProofSchema(%q) is not valid JSON", name)
		}
	}
}

func TestMapProofCorpusDigestIsImmutable(t *testing.T) {
	data, err := conformance.MapProofBytes()
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != "d4af2e419c00c367220a71e9d540d42b370154b74daaeb28f5259b8894cc0dcd" {
		t.Fatalf("Map-proof v1 corpus digest changed: %s", got)
	}
}

func TestMapProofCoverageMatrix(t *testing.T) {
	corpus, err := conformance.LoadMapProof()
	if err != nil {
		t.Fatalf("LoadMapProof: %v", err)
	}
	type coverageKey struct {
		backend  string
		category string
		valid    bool
	}
	covered := make(map[coverageKey]bool, len(corpus.Vectors))
	for _, vector := range corpus.Vectors {
		covered[coverageKey{vector.Backend, vector.Category, vector.Expected.Valid}] = true
	}
	for _, backend := range []string{conformance.BackendKZG, conformance.BackendIPA} {
		for _, required := range []coverageKey{
			{backend, "membership", true},
			{backend, "absence", true},
			{backend, "tamper", false},
			{backend, "cross_root", false},
			{backend, "wrong_key", false},
			{backend, "target_tamper", false},
			{backend, "strict_json", false},
		} {
			if !covered[required] {
				t.Errorf("missing coverage: backend=%s category=%s valid=%t", required.backend, required.category, required.valid)
			}
		}
	}
}

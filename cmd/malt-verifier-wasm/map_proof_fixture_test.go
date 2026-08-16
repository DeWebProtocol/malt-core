package main

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	malt "github.com/dewebprotocol/malt-core"
	"github.com/dewebprotocol/malt-core/auth/arcset"
	materialmemory "github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
	"github.com/dewebprotocol/malt-core/auth/commitment/kzg"
	"github.com/dewebprotocol/malt-core/auth/semantic/mapping"
	mapradix "github.com/dewebprotocol/malt-core/auth/semantic/mapping/radix"
	"github.com/dewebprotocol/malt-core/execution"
	"github.com/dewebprotocol/malt-core/protocol"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

const mapProofFixtureOperation = "map_proof"

type wasmMapProofFixtureSet struct {
	Vectors []wasmMapProofFixture `json:"vectors"`
}

type wasmMapProofFixture struct {
	ID           string                        `json:"id"`
	Operation    string                        `json:"operation"`
	Backend      maltcid.BackendKind           `json:"backend"`
	Category     string                        `json:"category"`
	Verification protocol.MapProofVerification `json:"verification"`
	Expected     wasmMapProofExpected          `json:"expected"`
}

type wasmMapProofExpected struct {
	Valid bool `json:"valid"`
}

func TestGenerateMapProofWASMFixtures(t *testing.T) {
	outputPath := os.Getenv("MALT_VERIFIER_WASM_MAP_PROOF_FIXTURE_OUT")
	if outputPath == "" {
		t.Skip("MALT_VERIFIER_WASM_MAP_PROOF_FIXTURE_OUT is not set")
	}

	fixtures := wasmMapProofFixtureSet{}
	for _, backend := range []maltcid.BackendKind{maltcid.BackendKindKZG, maltcid.BackendKindIPA} {
		fixtures.Vectors = append(fixtures.Vectors, mapProofWASMFixtures(t, backend)...)
	}
	data, err := json.Marshal(fixtures)
	if err != nil {
		t.Fatalf("marshal Map-proof WASM fixtures: %v", err)
	}
	if err := os.WriteFile(outputPath, data, 0o600); err != nil {
		t.Fatalf("write Map-proof WASM fixtures: %v", err)
	}
}

func mapProofWASMFixtures(t *testing.T, backend maltcid.BackendKind) []wasmMapProofFixture {
	t.Helper()
	ctx := context.Background()
	scope := "wasm-map-proof-" + string(backend)
	semantic, err := mapradix.NewMap(mapProofFixtureScheme(t, backend), materialmemory.New(true))
	if err != nil {
		t.Fatalf("create %s Map semantic: %v", backend, err)
	}
	target := mapProofFixtureCID(t, "present-"+string(backend))
	root, err := semantic.Commit(ctx, scope, mapping.NewViewFrom(map[string]cid.Cid{"present": target}))
	if err != nil {
		t.Fatalf("commit %s Map fixture: %v", backend, err)
	}
	executor, err := execution.NewExecutor(execution.Options{Scope: scope, Maps: semantic})
	if err != nil {
		t.Fatalf("create %s executor: %v", backend, err)
	}
	request := malt.MapProofRequest{Root: root, Key: arcset.CanonicalizePath("missing")}
	result, err := executor.ProveMap(ctx, request)
	if err != nil {
		t.Fatalf("prove %s Map absence: %v", backend, err)
	}
	if result.Present || result.Target.Defined() {
		t.Fatalf("%s Map absence result is present: %+v", backend, result)
	}
	wireRequest, err := protocol.NewMapProofRequest(request)
	if err != nil {
		t.Fatalf("encode %s Map-proof request: %v", backend, err)
	}
	wireResult, err := protocol.NewMapProofResult(result)
	if err != nil {
		t.Fatalf("encode %s Map-proof result: %v", backend, err)
	}
	accepted := protocol.MapProofVerification{Request: wireRequest, Result: wireResult}

	otherRoot, err := semantic.Commit(ctx, scope, mapping.NewViewFrom(map[string]cid.Cid{
		"other": mapProofFixtureCID(t, "other-"+string(backend)),
	}))
	if err != nil {
		t.Fatalf("commit alternate %s Map fixture: %v", backend, err)
	}

	proofTamper := cloneMapProofVerification(t, accepted)
	tamperMapProofEvidence(t, &proofTamper)
	crossRoot := cloneMapProofVerification(t, accepted)
	crossRoot.Request.Root = otherRoot.String()
	crossRoot.Result.ProofList.Root = otherRoot
	crossRoot.Result.ProofList.Steps[0].From = otherRoot
	wrongKey := cloneMapProofVerification(t, accepted)
	wrongKey.Request.Key = []string{"another-missing"}

	prefix := "map-proof." + string(backend) + ".absence."
	return []wasmMapProofFixture{
		mapProofFixture(prefix+"accept", backend, "absence", accepted, true),
		mapProofFixture(prefix+"proof-tamper.reject", backend, "tamper", proofTamper, false),
		mapProofFixture(prefix+"cross-root.reject", backend, "cross_root", crossRoot, false),
		mapProofFixture(prefix+"wrong-key.reject", backend, "wrong_key", wrongKey, false),
	}
}

func mapProofFixture(id string, backend maltcid.BackendKind, category string, verification protocol.MapProofVerification, valid bool) wasmMapProofFixture {
	return wasmMapProofFixture{
		ID: id, Operation: mapProofFixtureOperation, Backend: backend, Category: category,
		Verification: verification, Expected: wasmMapProofExpected{Valid: valid},
	}
}

func cloneMapProofVerification(t *testing.T, value protocol.MapProofVerification) protocol.MapProofVerification {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal Map-proof fixture: %v", err)
	}
	var cloned protocol.MapProofVerification
	if err := json.Unmarshal(data, &cloned); err != nil {
		t.Fatalf("clone Map-proof fixture: %v", err)
	}
	return cloned
}

func tamperMapProofEvidence(t *testing.T, value *protocol.MapProofVerification) {
	t.Helper()
	if value == nil || len(value.Result.ProofList.Steps) != 1 {
		t.Fatal("Map-proof fixture does not contain exactly one proof step")
	}
	var envelope struct {
		Steps []struct {
			Slot  []byte `json:"slot,omitempty"`
			Proof []byte `json:"proof"`
		} `json:"steps"`
		Bucket json.RawMessage `json:"bucket,omitempty"`
	}
	if err := json.Unmarshal(value.Result.ProofList.Steps[0].Proof, &envelope); err != nil {
		t.Fatalf("decode Map-proof evidence: %v", err)
	}
	if len(envelope.Steps) == 0 || len(envelope.Steps[0].Proof) < 4 {
		t.Fatal("Map-proof evidence has no mutable primitive proof")
	}
	envelope.Steps[0].Proof[len(envelope.Steps[0].Proof)-1] ^= 0x01
	tampered, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("encode tampered Map-proof evidence: %v", err)
	}
	value.Result.ProofList.Steps[0].Proof = tampered
}

func mapProofFixtureScheme(t *testing.T, backend maltcid.BackendKind) commitment.IndexCommitment {
	t.Helper()
	var (
		scheme commitment.IndexCommitment
		err    error
	)
	switch backend {
	case maltcid.BackendKindKZG:
		scheme, err = kzg.NewScheme()
	case maltcid.BackendKindIPA:
		scheme, err = ipa.NewScheme()
	default:
		t.Fatalf("unsupported Map-proof fixture backend %q", backend)
	}
	if err != nil {
		t.Fatalf("create %s commitment scheme: %v", backend, err)
	}
	return scheme
}

func mapProofFixtureCID(t *testing.T, seed string) cid.Cid {
	t.Helper()
	digest, err := mh.Sum([]byte("malt-map-proof-wasm-fixture:"+seed), mh.SHA2_256, -1)
	if err != nil {
		t.Fatalf("hash Map-proof fixture CID: %v", err)
	}
	return cid.NewCidV1(cid.Raw, digest)
}

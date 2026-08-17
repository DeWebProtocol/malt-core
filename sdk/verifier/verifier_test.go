package verifier_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/dewebprotocol/malt-core/artifact"
	clientverifier "github.com/dewebprotocol/malt-core/sdk/verifier"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
)

func TestDefaultVerifierAcceptsRootIdentityArtifact(t *testing.T) {
	data, err := os.ReadFile("../../artifact/testdata/v0alpha2/verify-root-request.json")
	if err != nil {
		t.Fatal(err)
	}
	var request artifact.VerifyRequest
	if err := json.Unmarshal(data, &request); err != nil {
		t.Fatal(err)
	}
	verifier, err := clientverifier.NewDefault()
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(context.Background(), clientverifier.Request{
		Profile:     artifact.Profile,
		TrustedRoot: request.Artifact.Root,
		Expected: clientverifier.Expectation{
			Operation: artifact.OperationResolve,
			Query:     artifact.Query{Kind: artifact.QueryPath, Segments: []string{}},
		},
		Artifact: request.Artifact,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestLocalRequestRejectsArtifactSelectedRoot(t *testing.T) {
	data, err := os.ReadFile("../../artifact/testdata/v0alpha2/verify-root-request.json")
	if err != nil {
		t.Fatal(err)
	}
	var request artifact.VerifyRequest
	if err := json.Unmarshal(data, &request); err != nil {
		t.Fatal(err)
	}
	verifier, err := clientverifier.NewDefault()
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(context.Background(), clientverifier.Request{
		Profile:     artifact.Profile,
		TrustedRoot: "bafkqaaa",
		Expected: clientverifier.Expectation{
			Operation: artifact.OperationResolve,
			Query:     artifact.Query{Kind: artifact.QueryPath, Segments: []string{}},
		},
		Artifact: request.Artifact,
	}); err == nil {
		t.Fatal("accepted an artifact under a different client-selected root")
	}
}

func TestLocalVerifyConformanceFixture(t *testing.T) {
	data, err := os.ReadFile("../../artifact/testdata/v0alpha2/local-verify-root-request.json")
	if err != nil {
		t.Fatal(err)
	}
	var request clientverifier.Request
	if err := json.Unmarshal(data, &request); err != nil {
		t.Fatal(err)
	}
	verifier, err := clientverifier.NewDefault()
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(context.Background(), request); err != nil {
		t.Fatalf("local fixture did not verify: %v", err)
	}
}

func TestDefaultVerifierRejectsTamperedIdentityTarget(t *testing.T) {
	data, err := os.ReadFile("../../artifact/testdata/v0alpha2/verify-root-request.json")
	if err != nil {
		t.Fatal(err)
	}
	var request artifact.VerifyRequest
	if err := json.Unmarshal(data, &request); err != nil {
		t.Fatal(err)
	}
	request.Artifact.Target = "bafkqaaa"
	verifier, err := clientverifier.NewDefault()
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(context.Background(), clientverifier.Request{
		Profile:     artifact.Profile,
		TrustedRoot: request.Artifact.Root,
		Expected: clientverifier.Expectation{
			Operation: artifact.OperationResolve,
			Query:     artifact.Query{Kind: artifact.QueryPath, Segments: []string{}},
		},
		Artifact: request.Artifact,
	}); err == nil {
		t.Fatal("accepted tampered artifact")
	}
}

func TestLocalRequestRejectsArtifactSelectedQuery(t *testing.T) {
	data, err := os.ReadFile("../../artifact/testdata/v0alpha2/verify-root-request.json")
	if err != nil {
		t.Fatal(err)
	}
	var request artifact.VerifyRequest
	if err := json.Unmarshal(data, &request); err != nil {
		t.Fatal(err)
	}
	verifier, err := clientverifier.NewDefault()
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(context.Background(), clientverifier.Request{
		Profile:     artifact.Profile,
		TrustedRoot: request.Artifact.Root,
		Expected: clientverifier.Expectation{
			Operation: artifact.OperationResolve,
			Query:     artifact.Query{Kind: artifact.QueryPath, Segments: []string{"docs"}},
		},
		Artifact: request.Artifact,
	}); err == nil {
		t.Fatal("accepted an artifact for a different client-selected query")
	}
}

func TestBackendSpecificVerifierRejectsUnsupportedBackend(t *testing.T) {
	for _, kind := range []maltcid.BackendKind{
		maltcid.BackendKindKZG,
		maltcid.BackendKindIPA,
	} {
		if _, err := clientverifier.NewForBackend(kind); err != nil {
			t.Fatalf("NewForBackend(%q): %v", kind, err)
		}
	}
	if _, err := clientverifier.NewForBackend(maltcid.BackendKindUnknown); err == nil {
		t.Fatal("NewForBackend accepted an unknown backend")
	}
}

package artifact_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"

	malt "github.com/dewebprotocol/malt-core"
	"github.com/dewebprotocol/malt-core/artifact"
	"github.com/dewebprotocol/malt-core/auth/proof/prooflist"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

type acceptingVerifier struct{}

func (acceptingVerifier) VerifyProofList(context.Context, prooflist.ProofList) (bool, error) {
	return true, nil
}

func TestVerifyResolveArtifactBindsSegmentsAndTarget(t *testing.T) {
	root := testCID(t, "root")
	target := testCID(t, "target")
	pl := prooflist.ProofList{
		Root:  root,
		Query: "a/b/c/d",
		Steps: []prooflist.Step{
			{Kind: prooflist.KindMapStep, From: root, Path: "a/b", Target: target},
		},
	}
	req := artifact.ResolveRequest{
		Profile:  artifact.Profile,
		Root:     root.String(),
		Segments: []string{"a", "b", "c", "d"},
	}
	// Build the complete existential derivation expected by the request.
	root2 := target
	target2 := testCID(t, "target-2")
	target3 := testCID(t, "target-3")
	pl.Steps = []prooflist.Step{
		{Kind: prooflist.KindMapStep, From: root, Path: "a/b", Target: root2},
		{Kind: prooflist.KindMapStep, From: root2, Path: "c", Target: target2},
		{Kind: prooflist.KindMapStep, From: target2, Path: "d", Target: target3},
	}
	art, err := artifact.NewResolveArtifact(req, target3, pl)
	if err != nil {
		t.Fatal(err)
	}
	if err := artifact.Verify(context.Background(), artifact.VerifyRequest{
		Profile: artifact.Profile, Artifact: art,
	}, acceptingVerifier{}); err != nil {
		t.Fatalf("Verify() failed: %v", err)
	}

	art.Target = testCID(t, "tampered").String()
	if err := artifact.Verify(context.Background(), artifact.VerifyRequest{
		Profile: artifact.Profile, Artifact: art,
	}, acceptingVerifier{}); err == nil {
		t.Fatal("Verify() accepted a tampered target")
	}
}

func TestResolveArtifactDoesNotRequireLongestOrUniqueProof(t *testing.T) {
	root := testCID(t, "root")
	target := testCID(t, "target")
	req := artifact.ResolveRequest{Profile: artifact.Profile, Root: root.String(), Segments: []string{"a", "b"}}
	pl := prooflist.ProofList{
		Root: root, Query: "a/b",
		Steps: []prooflist.Step{{Kind: prooflist.KindMapStep, From: root, Path: "a/b", Target: target}},
	}
	art, err := artifact.NewResolveArtifact(req, target, pl)
	if err != nil {
		t.Fatal(err)
	}
	if err := artifact.Verify(context.Background(), artifact.VerifyRequest{
		Profile: artifact.Profile, Artifact: art,
	}, acceptingVerifier{}); err != nil {
		t.Fatalf("Verify() failed: %v", err)
	}
}

func TestVerifyResolveArtifactRejectsPrimitiveReadEvidence(t *testing.T) {
	root := testCID(t, "list-root")
	target := testCID(t, "list-target")
	index, length := uint64(0), uint64(1)
	value := artifact.Artifact{
		Profile:   artifact.Profile,
		Operation: artifact.OperationResolve,
		Root:      root.String(),
		Query:     artifact.Query{Kind: artifact.QueryPath, Segments: []string{"list:0"}},
		Target:    target.String(),
		ProofList: prooflist.ProofList{
			Root:  root,
			Query: "list:0",
			Steps: []prooflist.Step{{
				Kind:   prooflist.KindListIndex,
				From:   root,
				Query:  "list:0",
				Index:  &index,
				Length: &length,
				Target: target,
			}},
		},
	}
	if err := artifact.Verify(context.Background(), artifact.VerifyRequest{
		Profile:  artifact.Profile,
		Artifact: value,
	}, acceptingVerifier{}); err == nil {
		t.Fatal("Verify() accepted list-index evidence as a resolve artifact")
	}
}

func TestPublishedSchemasAreJSONObjects(t *testing.T) {
	for _, name := range artifact.SchemaNames() {
		data, err := artifact.Schema(name)
		if err != nil {
			t.Fatalf("Schema(%q): %v", name, err)
		}
		var parsed map[string]any
		if err := json.Unmarshal(data, &parsed); err != nil {
			t.Fatalf("Schema(%q) is invalid JSON: %v", name, err)
		}
		if parsed["$schema"] == nil || parsed["$id"] == nil {
			t.Fatalf("Schema(%q) lacks identity metadata", name)
		}
	}
}

func TestQueryFromCoreRejectsUnsupportedKind(t *testing.T) {
	if _, err := artifact.QueryFromCore(malt.Query{Kind: malt.QueryKind("future")}); err == nil {
		t.Fatal("QueryFromCore accepted an unsupported query kind")
	}
}

func TestQueryEqualComparesPointerValuesAndSegments(t *testing.T) {
	indexA, indexB := uint64(7), uint64(7)
	left := artifact.Query{Kind: artifact.QueryListIndex, Index: &indexA}
	right := artifact.Query{Kind: artifact.QueryListIndex, Index: &indexB}
	if !left.Equal(right) {
		t.Fatal("equal list-index queries compared unequal")
	}
	right = artifact.Query{Kind: artifact.QueryPath, Segments: []string{"a", "b"}}
	if right.Equal(artifact.Query{Kind: artifact.QueryPath, Segments: []string{"a", "c"}}) {
		t.Fatal("different path queries compared equal")
	}
}

func TestQueryJSONMatchesConditionalSchemaShape(t *testing.T) {
	identity, err := json.Marshal(artifact.Query{Kind: artifact.QueryPath})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(identity, []byte(`"segments":[]`)) {
		t.Fatalf("identity query JSON = %s, want required empty segments", identity)
	}

	index := uint64(7)
	encodedIndex, err := json.Marshal(artifact.Query{Kind: artifact.QueryListIndex, Index: &index})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encodedIndex, []byte(`"segments"`)) {
		t.Fatalf("list-index query JSON contains unrelated segments: %s", encodedIndex)
	}

	var legacyIdentity artifact.Query
	if err := json.Unmarshal([]byte(`{"kind":"path"}`), &legacyIdentity); err != nil {
		t.Fatalf("decode v0.0.4 identity query: %v", err)
	}
	if legacyIdentity.Kind != artifact.QueryPath || len(legacyIdentity.Segments) != 0 {
		t.Fatalf("legacy identity query = %#v, want canonical zero-segment path", legacyIdentity)
	}
	canonicalIdentity, err := json.Marshal(legacyIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(canonicalIdentity, []byte(`"segments":[]`)) {
		t.Fatalf("canonicalized legacy identity query JSON = %s", canonicalIdentity)
	}

	for _, raw := range []string{
		`{"kind":"path","segments":null}`,
		`{"kind":"path","segments":[],"index":0}`,
		`{"kind":"list_index","index":0,"unexpected":true}`,
	} {
		var query artifact.Query
		if err := json.Unmarshal([]byte(raw), &query); err == nil {
			t.Fatalf("accepted schema-invalid query %s", raw)
		}
	}
}

func TestV004RootIdentityArtifactRemainsCompatible(t *testing.T) {
	data, err := os.ReadFile("testdata/v0alpha2/resolve-root-artifact-v004.json")
	if err != nil {
		t.Fatal(err)
	}
	var value artifact.Artifact
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatalf("decode v0.0.4 root identity artifact: %v", err)
	}
	if err := value.Validate(); err != nil {
		t.Fatalf("validate v0.0.4 root identity artifact: %v", err)
	}
	if len(value.Query.Segments) != 0 {
		t.Fatalf("identity segments = %v, want empty", value.Query.Segments)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte(`"query":{"kind":"path","segments":[]}`)) {
		t.Fatalf("canonical artifact JSON did not restore empty segments: %s", encoded)
	}
}

func TestRootIdentityConformanceFixture(t *testing.T) {
	data, err := os.ReadFile("testdata/v0alpha2/verify-root-request.json")
	if err != nil {
		t.Fatal(err)
	}
	var request artifact.VerifyRequest
	if err := json.Unmarshal(data, &request); err != nil {
		t.Fatal(err)
	}
	if err := artifact.Verify(context.Background(), request, acceptingVerifier{}); err != nil {
		t.Fatalf("fixture did not verify: %v", err)
	}
}

func testCID(t *testing.T, seed string) cid.Cid {
	t.Helper()
	hash, err := mh.Sum([]byte(seed), mh.SHA2_256, -1)
	if err != nil {
		t.Fatal(err)
	}
	return cid.NewCidV1(cid.Raw, hash)
}

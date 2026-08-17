package resolver_test

import (
	"context"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	materialmemory "github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment/kzg"
	"github.com/dewebprotocol/malt-core/auth/proof/evidence"
	"github.com/dewebprotocol/malt-core/auth/semantic/mapping"
	mappingradix "github.com/dewebprotocol/malt-core/auth/semantic/mapping/radix"
	"github.com/dewebprotocol/malt-core/graph/resolver"
	"github.com/dewebprotocol/malt-core/graph/resolver/step/explicit"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

// newPayloadCID creates a CID from data for testing.
func newPayloadCID(data []byte) (cid.Cid, error) {
	mhash, err := mh.Sum(data, mh.SHA2_256, -1)
	if err != nil {
		return cid.Cid{}, err
	}
	return cid.NewCidV1(cid.Raw, mhash), nil
}

// newTestMaterializer creates a new ArcSet materializer for testing.
func newTestMaterializer() *materialmemory.Store {
	return materialmemory.New(true)
}

func newSemantic(t *testing.T, e *materialmemory.Store) mapping.Semantics {
	t.Helper()
	scheme, err := kzg.NewScheme()
	if err != nil {
		t.Fatalf("NewScheme failed: %v", err)
	}
	semantic, err := mappingradix.NewMap(scheme, e)
	if err != nil {
		t.Fatalf("radix.NewMap failed: %v", err)
	}
	return semantic
}

func commitStructure(t *testing.T, ctx context.Context, semantic mapping.Semantics, e *materialmemory.Store, namespace string, arcs map[string]cid.Cid) cid.Cid {
	t.Helper()
	root, err := semantic.Commit(ctx, namespace, mapping.NewViewFrom(arcs))
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}
	if err := e.Update(ctx, namespace, root, cid.Undef, arcset.NewSetFrom(arcs)); err != nil {
		t.Fatalf("ArcSet materializer.Update failed: %v", err)
	}
	return root
}

const testNamespace = "test-graph"

func TestResolverExplicitOnly(t *testing.T) {
	e := newTestMaterializer()
	semantic := newSemantic(t, e)

	ctx := context.Background()
	k1, _ := newPayloadCID([]byte("target1"))
	k2, _ := newPayloadCID([]byte("target2"))
	k3, _ := newPayloadCID([]byte("target3"))

	arcsMap := map[string]cid.Cid{
		"a":     k1,
		"a/b":   k2,
		"a/b/c": k3,
	}
	root := commitStructure(t, ctx, semantic, e, testNamespace, arcsMap)

	explicitR := explicit.NewResolver(e, semantic, testNamespace)
	g := resolver.NewResolver(explicitR)

	tests := []struct {
		path     string
		expected cid.Cid
	}{
		{"a", k1},
		{"a/b", k2},
		{"a/b/c", k3},
	}

	for _, tt := range tests {
		result, err := g.Resolve(ctx, root, tt.path)
		if err != nil {
			t.Errorf("Resolve(%s) failed: %v", tt.path, err)
			continue
		}
		if !result.Target.Equals(tt.expected) {
			t.Errorf("Resolve(%s) = %v, want %v", tt.path, result.Target, tt.expected)
		}
		if len(result.Transcript.Steps) != 1 {
			t.Errorf("Resolve(%s) should have exactly one step, got %d", tt.path, len(result.Transcript.Steps))
		}

		valid, err := g.VerifyTranscript(ctx, root, result.Transcript)
		if err != nil {
			t.Errorf("VerifyTranscript(%s) failed: %v", tt.path, err)
		}
		if !valid {
			t.Errorf("VerifyTranscript(%s) should be valid", tt.path)
		}
	}
}

func TestResolverCanonicalizesResolvePath(t *testing.T) {
	e := newTestMaterializer()
	semantic := newSemantic(t, e)

	ctx := context.Background()
	target, _ := newPayloadCID([]byte("target"))
	arcsMap := map[string]cid.Cid{
		"a/b": target,
	}
	root := commitStructure(t, ctx, semantic, e, testNamespace, arcsMap)

	explicitR := explicit.NewResolver(e, semantic, testNamespace)
	g := resolver.NewResolver(explicitR)

	result, err := g.Resolve(ctx, root, "/a//b/")
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if !result.Target.Equals(target) {
		t.Errorf("Resolve(/a//b/) = %v, want %v", result.Target, target)
	}
	if len(result.Transcript.Steps) != 1 || result.Transcript.Steps[0].Path != "a/b" {
		t.Errorf("expected canonical transcript path a/b, got %+v", result.Transcript.Steps)
	}
}

func TestResolverExplicitLongestPrefix(t *testing.T) {
	e := newTestMaterializer()
	semantic := newSemantic(t, e)

	ctx := context.Background()
	k1, _ := newPayloadCID([]byte("target1"))
	k2, _ := newPayloadCID([]byte("target2"))
	k3, _ := newPayloadCID([]byte("target3"))

	arcsMap := map[string]cid.Cid{
		"a":     k1,
		"a/b":   k2,
		"a/b/c": k3,
	}
	root := commitStructure(t, ctx, semantic, e, testNamespace, arcsMap)

	explicitR := explicit.NewResolver(e, semantic, testNamespace)
	g := resolver.NewResolver(explicitR)

	result, err := g.Resolve(ctx, root, "a/b/c/d")
	if err == nil && !result.Target.Equals(k3) {
		t.Errorf("Resolve(a/b/c/d) = %v, want %v", result.Target, k3)
	}
}

func TestResolverStopsAtNonMaltPayload(t *testing.T) {
	e := newTestMaterializer()
	semantic := newSemantic(t, e)

	ctx := context.Background()
	payloadCID, _ := newPayloadCID([]byte("raw-block-data"))
	arcsMap := map[string]cid.Cid{"data": payloadCID}
	root := commitStructure(t, ctx, semantic, e, testNamespace, arcsMap)

	explicitR := explicit.NewResolver(e, semantic, testNamespace)
	g := resolver.NewResolver(explicitR)

	result, err := g.Resolve(ctx, root, "data")
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if !result.Target.Defined() {
		t.Error("Target should be defined")
	}
	if len(result.Transcript.Steps) != 1 {
		t.Errorf("Expected 1 step, got %d", len(result.Transcript.Steps))
	}
}

func TestResolverTranscript(t *testing.T) {
	e := newTestMaterializer()
	semantic := newSemantic(t, e)

	ctx := context.Background()
	innerCID, _ := newPayloadCID([]byte("inner"))
	outerCID, _ := newPayloadCID([]byte("outer"))

	arcsMap := map[string]cid.Cid{
		"inner": innerCID,
		"outer": outerCID,
	}
	root := commitStructure(t, ctx, semantic, e, testNamespace, arcsMap)

	explicitR := explicit.NewResolver(e, semantic, testNamespace)
	g := resolver.NewResolver(explicitR)

	result, err := g.Resolve(ctx, root, "inner")
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if len(result.Transcript.Steps) != 1 {
		t.Errorf("Expected 1 step, got %d", len(result.Transcript.Steps))
	}

	step := result.Transcript.Steps[0]
	if step.Path != "inner" {
		t.Errorf("Step path = %s, want inner", step.Path)
	}
	if !step.Target.Equals(innerCID) {
		t.Error("Step target should match innerCID")
	}
	if step.Evidence.Kind() != evidence.EvidenceKindExplicit {
		t.Error("Step evidence should be ExplicitEvidence")
	}
}

func TestResolverPayloadRedirect(t *testing.T) {
	e := newTestMaterializer()
	semantic := newSemantic(t, e)

	ctx := context.Background()
	payloadCID, _ := newPayloadCID([]byte("payload-data"))
	arcsMap := map[string]cid.Cid{
		"@payload": payloadCID,
		"link":     payloadCID,
	}
	root := commitStructure(t, ctx, semantic, e, testNamespace, arcsMap)

	explicitR := explicit.NewResolver(e, semantic, testNamespace)
	g := resolver.NewResolver(explicitR)

	result, err := g.Resolve(ctx, root, "")
	if err != nil {
		t.Fatalf("Resolve with empty path failed: %v", err)
	}
	if !result.Target.Equals(payloadCID) {
		t.Errorf("Empty path resolve target = %v, want payloadCID %v", result.Target, payloadCID)
	}
	if len(result.Transcript.Steps) != 1 {
		t.Errorf("Expected 1 step, got %d", len(result.Transcript.Steps))
	}
	if result.Transcript.Steps[0].Path != "@payload" {
		t.Errorf("Step path = %s, want @payload", result.Transcript.Steps[0].Path)
	}

	valid, err := g.VerifyTranscript(ctx, root, result.Transcript)
	if err != nil {
		t.Fatalf("VerifyTranscript failed: %v", err)
	}
	if !valid {
		t.Error("Transcript should be valid")
	}
}

func TestResolveKeyAndResolve_ListTerminalNoPayloadRedirect(t *testing.T) {
	e := newTestMaterializer()
	semantic := newSemantic(t, e)

	ctx := context.Background()
	commitment := make([]byte, maltcid.KZGCommitmentSize)
	for i := range commitment {
		commitment[i] = byte(i + 1)
	}
	listRoot, err := maltcid.NewListKZGCid(commitment)
	if err != nil {
		t.Fatalf("NewListKZGCid failed: %v", err)
	}
	root := commitStructure(t, ctx, semantic, e, testNamespace, map[string]cid.Cid{
		"file": listRoot,
	})

	explicitR := explicit.NewResolver(e, semantic, testNamespace)
	g := resolver.NewResolver(explicitR)

	keyResult, err := g.ResolveKey(ctx, root, "file")
	if err != nil {
		t.Fatalf("ResolveKey failed: %v", err)
	}
	if !keyResult.Target.Equals(listRoot) {
		t.Fatalf("ResolveKey target = %v, want %v", keyResult.Target, listRoot)
	}
	if len(keyResult.Transcript.Steps) != 1 {
		t.Fatalf("ResolveKey steps = %d, want 1", len(keyResult.Transcript.Steps))
	}

	resolveResult, err := g.Resolve(ctx, root, "file")
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if !resolveResult.Target.Equals(listRoot) {
		t.Fatalf("Resolve target = %v, want list root %v", resolveResult.Target, listRoot)
	}
	if len(resolveResult.Transcript.Steps) != 1 {
		t.Fatalf("Resolve should not append @payload for list; steps = %d", len(resolveResult.Transcript.Steps))
	}

	incompleteResult, err := g.Resolve(ctx, root, "file/extra")
	if err != nil {
		t.Fatalf("Resolve incomplete list path failed: %v", err)
	}
	if !incompleteResult.Target.Equals(listRoot) {
		t.Fatalf("Resolve incomplete list target = %v, want list root %v", incompleteResult.Target, listRoot)
	}
	if incompleteResult.RemainingPath != "extra" {
		t.Fatalf("Resolve incomplete list remaining path = %q, want %q", incompleteResult.RemainingPath, "extra")
	}
	if len(incompleteResult.Transcript.Steps) != 1 {
		t.Fatalf("Resolve incomplete list steps = %d, want 1", len(incompleteResult.Transcript.Steps))
	}
}

func TestResolverMissingPayloadBindingFails(t *testing.T) {
	e := newTestMaterializer()
	semantic := newSemantic(t, e)

	ctx := context.Background()
	targetCID, _ := newPayloadCID([]byte("target-data"))
	arcsMap := map[string]cid.Cid{"link": targetCID}
	root := commitStructure(t, ctx, semantic, e, testNamespace, arcsMap)

	explicitR := explicit.NewResolver(e, semantic, testNamespace)
	g := resolver.NewResolver(explicitR)

	result, err := g.Resolve(ctx, root, "")
	if err == nil {
		t.Fatalf("Resolve unexpectedly succeeded: %+v", result)
	}
}

func TestResolverNonMaltEmptyPathIsTerminal(t *testing.T) {
	e := newTestMaterializer()
	semantic := newSemantic(t, e)

	ctx := context.Background()
	payloadCID, _ := newPayloadCID([]byte("raw-data"))

	explicitR := explicit.NewResolver(e, semantic, testNamespace)
	g := resolver.NewResolver(explicitR)

	result, err := g.Resolve(ctx, payloadCID, "")
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if !result.Target.Equals(payloadCID) {
		t.Errorf("Target = %v, want %v", result.Target, payloadCID)
	}
	if len(result.Transcript.Steps) != 0 {
		t.Errorf("Expected 0 steps, got %d", len(result.Transcript.Steps))
	}
}

func TestResolverNonMaltPathReportsRemaining(t *testing.T) {
	e := newTestMaterializer()
	semantic := newSemantic(t, e)

	ctx := context.Background()
	payloadCID, _ := newPayloadCID([]byte("raw-data"))

	explicitR := explicit.NewResolver(e, semantic, testNamespace)
	g := resolver.NewResolver(explicitR)

	result, err := g.Resolve(ctx, payloadCID, "missing/path")
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if !result.Target.Equals(payloadCID) {
		t.Fatalf("Target = %v, want %v", result.Target, payloadCID)
	}
	if result.RemainingPath != "missing/path" {
		t.Fatalf("RemainingPath = %q, want %q", result.RemainingPath, "missing/path")
	}
	if len(result.Transcript.Steps) != 0 {
		t.Fatalf("Expected 0 steps, got %d", len(result.Transcript.Steps))
	}
}

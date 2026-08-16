package runtimegraph

import (
	"context"
	"strings"
	"testing"

	malt "github.com/dewebprotocol/malt-core"
	"github.com/dewebprotocol/malt-core/auth/arcset"
	materialmemory "github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
	"github.com/dewebprotocol/malt-core/auth/commitment/kzg"
	"github.com/dewebprotocol/malt-core/auth/semantic/list"
	clientverifier "github.com/dewebprotocol/malt-core/sdk/verifier"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

type fixedWidthCommitOnlyMeasuredSemantics struct {
	list.MeasuredSemantics
	committer list.FixedWidthCommitter
}

func (s fixedWidthCommitOnlyMeasuredSemantics) CommitFixed(ctx context.Context, namespace string, chunks []cid.Cid, chunkSize, totalSize uint64) (cid.Cid, error) {
	return s.committer.CommitFixed(ctx, namespace, chunks, chunkSize, totalSize)
}

type fixedWidthAppendOnlyMeasuredSemantics struct {
	list.MeasuredSemantics
	appender list.FixedWidthAppender
}

func (s fixedWidthAppendOnlyMeasuredSemantics) AppendFixed(ctx context.Context, namespace string, root cid.Cid, key cid.Cid, totalSize uint64) (cid.Cid, uint64, error) {
	return s.appender.AppendFixed(ctx, namespace, root, key, totalSize)
}

func TestNewGraphInitializesSDKComposition(t *testing.T) {
	store := materialmemory.New(true)
	g, err := NewGraph("composition", store, WithNamespace("ns"))
	if err != nil {
		t.Fatalf("NewGraph failed: %v", err)
	}

	if g.ID() != "composition" {
		t.Fatalf("ID = %q, want composition", g.ID())
	}
	if g.Namespace() != "ns" {
		t.Fatalf("Namespace = %q, want ns", g.Namespace())
	}
	if g.Resolver() == nil || g.Writer() == nil || g.StructureCreator() == nil || g.ReferenceWriter() == nil {
		t.Fatal("resolver, mutation, bootstrap, and reference capabilities must be initialized")
	}
	if g.Semantic() == nil || g.ListSemantic() == nil {
		t.Fatal("semantic implementations must be initialized")
	}
}

func TestRuntimeGraphDispatchesEachResolveStepByTypedRootBackend(t *testing.T) {
	ctx := context.Background()
	store := materialmemory.New(true)
	kzgScheme, err := kzg.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	ipaScheme, err := ipa.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	dynamic, err := NewGraph("dynamic", store,
		WithNamespace("mixed"),
		WithCommitmentBackend(maltcid.BackendKindKZG, kzgScheme),
		WithCommitmentBackend(maltcid.BackendKindIPA, ipaScheme),
		WithDefaultCommitmentBackend(maltcid.BackendKindKZG),
	)
	if err != nil {
		t.Fatal(err)
	}
	kzgGraph, err := NewGraph("kzg", store, WithNamespace("mixed"), WithCommitmentScheme(kzgScheme))
	if err != nil {
		t.Fatal(err)
	}
	ipaGraph, err := NewGraph("ipa", store, WithNamespace("mixed"), WithCommitmentScheme(ipaScheme))
	if err != nil {
		t.Fatal(err)
	}

	target := cid.MustParse("bafkqaaa")
	childSet, err := arcset.NewArcSet(map[string]cid.Cid{"name": target})
	if err != nil {
		t.Fatal(err)
	}
	childRoot, err := ipaGraph.StructureCreator().CreateStructure(ctx, "mixed", childSet)
	if err != nil {
		t.Fatal(err)
	}
	parentSet, err := arcset.NewArcSet(map[string]cid.Cid{"child": childRoot})
	if err != nil {
		t.Fatal(err)
	}
	parentRoot, err := kzgGraph.StructureCreator().CreateStructure(ctx, "mixed", parentSet)
	if err != nil {
		t.Fatal(err)
	}

	request := malt.ResolveRequest{Root: parentRoot, Segments: []string{"child", "name"}}
	result, err := dynamic.Resolve(ctx, request)
	if err != nil {
		t.Fatalf("mixed-backend resolve: %v", err)
	}
	if !result.Target.Equals(target) || len(result.ProofList.Steps) != 2 {
		t.Fatalf("mixed-backend result = %#v", result)
	}
	if maltcid.BackendKindOf(result.ProofList.Steps[0].From) != maltcid.BackendKindKZG ||
		maltcid.BackendKindOf(result.ProofList.Steps[1].From) != maltcid.BackendKindIPA {
		t.Fatalf("proof step backends = %s, %s", maltcid.BackendKindOf(result.ProofList.Steps[0].From), maltcid.BackendKindOf(result.ProofList.Steps[1].From))
	}
	verifier, err := clientverifier.NewDefault()
	if err != nil {
		t.Fatal(err)
	}
	if err := malt.VerifyResolve(ctx, request, result, verifier); err != nil {
		t.Fatalf("verify mixed-backend resolve: %v", err)
	}
}

func TestRuntimeGraphDispatchesListProofsAndKeepsCreateDefault(t *testing.T) {
	ctx := context.Background()
	store := materialmemory.New(true)
	kzgScheme, err := kzg.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	ipaScheme, err := ipa.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	dynamic, err := NewGraph("dynamic", store,
		WithNamespace("mixed-list"),
		WithCommitmentBackend(maltcid.BackendKindKZG, kzgScheme),
		WithCommitmentBackend(maltcid.BackendKindIPA, ipaScheme),
		WithDefaultCommitmentBackend(maltcid.BackendKindKZG),
	)
	if err != nil {
		t.Fatal(err)
	}
	ipaGraph, err := NewGraph("ipa", store, WithNamespace("mixed-list"), WithCommitmentScheme(ipaScheme))
	if err != nil {
		t.Fatal(err)
	}

	values := []cid.Cid{cid.MustParse("bafkqaaa"), cid.MustParse("bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku")}
	ipaRoot, err := ipaGraph.ListSemantic().Commit(ctx, "mixed-list", list.NewViewFromSlice(values))
	if err != nil {
		t.Fatal(err)
	}
	query, proof, err := dynamic.ListSemantic().Prove(ctx, "mixed-list", ipaRoot, 1)
	if err != nil {
		t.Fatalf("prove IPA list with KZG default: %v", err)
	}
	valid, err := dynamic.ListSemantic().Verify(ipaRoot, 1, query, proof)
	if err != nil || !valid {
		t.Fatalf("verify IPA list with KZG default = %v, %v", valid, err)
	}

	defaultRoot, err := dynamic.ListSemantic().Commit(ctx, "mixed-list", list.NewViewFromSlice(values))
	if err != nil {
		t.Fatal(err)
	}
	if got := maltcid.BackendKindOf(defaultRoot); got != maltcid.BackendKindKZG {
		t.Fatalf("default list backend = %s, want KZG", got)
	}
	if _, _, err := dynamic.Semantic().Prove(ctx, "mixed-list", ipaRoot, arcset.CanonicalizePath("name")); err == nil || !strings.Contains(err.Error(), "expected map") {
		t.Fatalf("map prover accepted list root: %v", err)
	}

	fixedCommitter := ipaGraph.ListSemantic().(list.FixedWidthSemantics)
	fixedRoot, err := fixedCommitter.CommitFixed(ctx, "mixed-list", values[:1], 4, 4)
	if err != nil {
		t.Fatal(err)
	}
	fixedAppender := dynamic.ListSemantic().(list.FixedWidthSemantics)
	appendedRoot, index, err := fixedAppender.AppendFixed(ctx, "mixed-list", fixedRoot, values[1], 8)
	if err != nil {
		t.Fatalf("append IPA fixed list with KZG default: %v", err)
	}
	if index != 1 || maltcid.BackendKindOf(appendedRoot) != maltcid.BackendKindIPA {
		t.Fatalf("fixed append root=%s index=%d", maltcid.BackendKindOf(appendedRoot), index)
	}
}

func TestListBackendDispatcherSupportsNarrowFixedWidthCapabilities(t *testing.T) {
	ctx := context.Background()
	store := materialmemory.New(true)
	scheme, err := kzg.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	g, err := NewGraph("narrow-fixed", store, WithNamespace("narrow-fixed"), WithCommitmentScheme(scheme))
	if err != nil {
		t.Fatal(err)
	}

	measured := g.ListSemantic().(list.MeasuredSemantics)
	fixed := measured.(list.FixedWidthSemantics)
	values := []cid.Cid{cid.MustParse("bafkqaaa"), cid.MustParse("bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku")}
	baseRoot, err := fixed.CommitFixed(ctx, "narrow-fixed", values[:1], 4, 4)
	if err != nil {
		t.Fatal(err)
	}
	expectedRoot, err := fixed.CommitFixed(ctx, "narrow-fixed", values, 4, 8)
	if err != nil {
		t.Fatal(err)
	}

	commitBackend := fixedWidthCommitOnlyMeasuredSemantics{MeasuredSemantics: measured, committer: fixed}
	if _, ok := any(commitBackend).(list.FixedWidthAppender); ok {
		t.Fatal("commit-only runtime fixture unexpectedly implements FixedWidthAppender")
	}
	commitDispatcher := &listBackendDispatcher{
		defaultBackend: maltcid.BackendKindKZG,
		backends: map[maltcid.BackendKind]list.MeasuredSemantics{
			maltcid.BackendKindKZG: commitBackend,
		},
	}
	committedRoot, err := commitDispatcher.CommitFixed(ctx, "narrow-fixed", values, 4, 8)
	if err != nil {
		t.Fatalf("CommitFixed through commit-only backend failed: %v", err)
	}
	if !committedRoot.Equals(expectedRoot) {
		t.Fatalf("committed root = %s, want %s", committedRoot, expectedRoot)
	}

	appendBackend := fixedWidthAppendOnlyMeasuredSemantics{MeasuredSemantics: measured, appender: fixed}
	if _, ok := any(appendBackend).(list.FixedWidthCommitter); ok {
		t.Fatal("append-only runtime fixture unexpectedly implements FixedWidthCommitter")
	}
	appendDispatcher := &listBackendDispatcher{
		defaultBackend: maltcid.BackendKindKZG,
		backends: map[maltcid.BackendKind]list.MeasuredSemantics{
			maltcid.BackendKindKZG: appendBackend,
		},
	}
	appendedRoot, index, err := appendDispatcher.AppendFixed(ctx, "narrow-fixed", baseRoot, values[1], 8)
	if err != nil {
		t.Fatalf("AppendFixed through append-only backend failed: %v", err)
	}
	if index != 1 || !appendedRoot.Equals(expectedRoot) {
		t.Fatalf("append result root=%s index=%d, want root=%s index=1", appendedRoot, index, expectedRoot)
	}
}

func TestRuntimeGraphBackendRegistrationValidation(t *testing.T) {
	store := materialmemory.New(true)
	kzgScheme, err := kzg.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	ipaScheme, err := ipa.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewGraph("missing-default", store,
		WithCommitmentBackend(maltcid.BackendKindKZG, kzgScheme),
		WithCommitmentBackend(maltcid.BackendKindIPA, ipaScheme),
	); err == nil || !strings.Contains(err.Error(), "default commitment backend is required") {
		t.Fatalf("missing default error = %v", err)
	}
	if _, err := NewGraph("mixed-options", store,
		WithCommitmentScheme(kzgScheme),
		WithCommitmentBackend(maltcid.BackendKindKZG, kzgScheme),
	); err == nil || !strings.Contains(err.Error(), "cannot be combined") {
		t.Fatalf("mixed option error = %v", err)
	}
}

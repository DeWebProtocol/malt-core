package execution_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/dewebprotocol/malt-core"
	"github.com/dewebprotocol/malt-core/auth/arcset"
	"github.com/dewebprotocol/malt-core/auth/proof/prooflist"
	structure "github.com/dewebprotocol/malt-core/auth/semantic"
	"github.com/dewebprotocol/malt-core/auth/semantic/list"
	"github.com/dewebprotocol/malt-core/auth/semantic/mapping"
	"github.com/dewebprotocol/malt-core/execution"
	"github.com/dewebprotocol/malt-core/mutation"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

func TestExecutorReadMapAndVerifyBindsRequest(t *testing.T) {
	root := testCID(t, "root")
	target := testCID(t, "target")
	key, err := arcset.NewPath("profile/name")
	if err != nil {
		t.Fatal(err)
	}
	maps := &fakeMaps{root: root, key: key, target: target, proof: []byte("map-proof")}
	engine, err := execution.NewExecutor(execution.Options{
		Scope: "physical-scope",
		Maps:  maps,
	})
	if err != nil {
		t.Fatal(err)
	}
	query, err := malt.MapKeyQuery("profile/name")
	if err != nil {
		t.Fatal(err)
	}
	req := malt.ReadRequest{Root: root, Query: query}
	result, err := engine.Read(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Target.Equals(target) {
		t.Fatalf("target = %s, want %s", result.Target, target)
	}
	if maps.scope != "physical-scope" {
		t.Fatalf("map scope = %q", maps.scope)
	}
	if err := malt.VerifyRead(context.Background(), req, result, acceptingVerifier{}); err != nil {
		t.Fatalf("VerifyRead: %v", err)
	}

	tampered := result
	tampered.Target = testCID(t, "tampered")
	if err := malt.VerifyRead(context.Background(), req, tampered, acceptingVerifier{}); err == nil {
		t.Fatal("VerifyRead accepted a target not bound by ProofList")
	}
}

func TestExecutorProveMapReturnsAndBindsAbsence(t *testing.T) {
	root := testCID(t, "absence-root")
	key := arcset.CanonicalizePath("profile/missing")
	maps := &fakeAbsentMaps{root: root, key: key, proof: []byte("absence-proof")}
	engine, err := execution.NewExecutor(execution.Options{Scope: "absence-scope", Maps: maps})
	if err != nil {
		t.Fatal(err)
	}
	request := malt.MapProofRequest{Root: root, Key: key}
	result, err := engine.ProveMap(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Present || result.Target.Defined() || maps.scope != "absence-scope" {
		t.Fatalf("absence result/scope = %+v/%q", result, maps.scope)
	}
	step := result.ProofList.Steps[0]
	if step.Kind != prooflist.KindMapAbsence || step.Target.Defined() {
		t.Fatalf("absence step = %+v", step)
	}
	if err := malt.VerifyMapProof(context.Background(), request, result, acceptingVerifier{}); err != nil {
		t.Fatalf("VerifyMapProof: %v", err)
	}

	tampered := result
	tampered.Present = true
	tampered.Target = testCID(t, "forged")
	if err := malt.VerifyMapProof(context.Background(), request, tampered, acceptingVerifier{}); err == nil {
		t.Fatal("VerifyMapProof accepted an absent proof as membership")
	}
	wrongKey := request
	wrongKey.Key = arcset.CanonicalizePath("profile/other")
	if err := malt.VerifyMapProof(context.Background(), wrongKey, result, acceptingVerifier{}); err == nil {
		t.Fatal("VerifyMapProof accepted an absence proof for another key")
	}
}

func TestExecutorResolveAndVerifyBindsRequest(t *testing.T) {
	root := testCID(t, "resolve-root")
	target := testCID(t, "resolve-target")
	path, err := arcset.NewPath("profile/name")
	if err != nil {
		t.Fatal(err)
	}
	paths := &fakePathResolver{result: malt.ResolveResult{
		Target: target,
		ProofList: prooflist.ProofList{Root: root, Query: path.String(), Steps: []prooflist.Step{{
			Kind:   prooflist.KindMapStep,
			From:   root,
			Path:   path.String(),
			Target: target,
		}}},
	}}
	engine, err := execution.NewExecutor(execution.Options{
		Scope:    "resolve-scope",
		Resolver: paths,
	})
	if err != nil {
		t.Fatal(err)
	}
	req := malt.ResolveRequest{Root: root, Segments: []string{"profile", "name"}}
	result, err := engine.Resolve(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	receivedPath, err := malt.NewSegmentPath(paths.request.Segments)
	if err != nil {
		t.Fatal(err)
	}
	if !paths.request.Root.Equals(root) || receivedPath.String() != "profile/name" || !result.Target.Equals(target) {
		t.Fatalf("request/target = %+v/%s, want profile/name/%s", paths.request, result.Target, target)
	}
	if err := malt.VerifyResolve(context.Background(), req, result, acceptingVerifier{}); err != nil {
		t.Fatalf("VerifyResolve: %v", err)
	}
}

func TestExecutorResolveIdentityDoesNotRequireRuntimeCapability(t *testing.T) {
	root := testCID(t, "identity-root")
	engine, err := execution.NewExecutor(execution.Options{
		Scope:  "identity-scope",
		Writer: &fakeWriter{},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := malt.ResolveRequest{Root: root, Segments: []string{}}
	result, err := engine.Resolve(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if err := malt.VerifyResolve(context.Background(), req, result, acceptingVerifier{}); err != nil {
		t.Fatalf("VerifyResolve identity: %v", err)
	}
}

func TestExecutorReadPayloadUsesTerminalProofKind(t *testing.T) {
	root := testCID(t, "payload-root")
	target := testCID(t, "payload-target")
	engine, err := execution.NewExecutor(execution.Options{
		Scope: "payload-scope",
		Maps: &fakeMaps{
			root:   root,
			key:    arcset.PayloadPath,
			target: target,
			proof:  []byte("payload-proof"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	query, err := malt.MapKeyQuery(arcset.PayloadPath.String())
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.Read(context.Background(), malt.ReadRequest{Root: root, Query: query})
	if err != nil {
		t.Fatal(err)
	}
	if got := result.ProofList.Steps[0].Kind; got != prooflist.KindPayloadBinding {
		t.Fatalf("proof kind = %q, want %q", got, prooflist.KindPayloadBinding)
	}
}

func TestExecutorReadListIndex(t *testing.T) {
	root := testCID(t, "list-root")
	target := testCID(t, "list-target")
	lists := fakeLists{root: root, target: target, length: 4, proof: []byte("list-proof")}
	engine, err := execution.NewExecutor(execution.Options{
		Scope: "list-scope",
		Lists: lists,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.Read(context.Background(), malt.ReadRequest{
		Root:  root,
		Query: malt.ListIndexQuery(2),
	})
	if err != nil {
		t.Fatal(err)
	}
	step := result.ProofList.Steps[0]
	if step.Kind != prooflist.KindListIndex || step.Index == nil || *step.Index != 2 {
		t.Fatalf("list step = %+v", step)
	}
}

func TestExecutorReadListRangeAndVerifyBindsSegments(t *testing.T) {
	root := testCID(t, "range-root")
	segments := []cid.Cid{testCID(t, "segment-a"), testCID(t, "segment-b")}
	lists := fakeMeasuredLists{
		root: root,
		result: list.RangeResult{
			Metadata: list.RangeMetadata{ChildCount: 2, TotalSize: 16, ChunkSize: 8},
			Segments: segments,
		},
		proof: []byte("range-proof"),
	}
	engine, err := execution.NewExecutor(execution.Options{
		Scope: "range-scope",
		Lists: lists,
	})
	if err != nil {
		t.Fatal(err)
	}
	end := uint64(10)
	query, err := malt.ListRangeQuery(2, &end)
	if err != nil {
		t.Fatal(err)
	}
	req := malt.ReadRequest{Root: root, Query: query}
	result, err := engine.Read(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Segments) != 2 || !result.Segments[0].Equals(segments[0]) || !result.Segments[1].Equals(segments[1]) {
		t.Fatalf("segments = %v, want %v", result.Segments, segments)
	}
	if err := malt.VerifyRead(context.Background(), req, result, acceptingVerifier{}); err != nil {
		t.Fatalf("VerifyRead: %v", err)
	}

	tampered := result
	tampered.Segments = []cid.Cid{segments[1]}
	if err := malt.VerifyRead(context.Background(), req, tampered, acceptingVerifier{}); err == nil {
		t.Fatal("VerifyRead accepted segments not bound by ProofList")
	}
}

func TestExecutorApplyHidesRuntimeScope(t *testing.T) {
	root := testCID(t, "base")
	newRoot := testCID(t, "next")
	applier := &fakeWriter{receipt: mutation.WriteReceipt{BaseRoot: root, NewRoot: newRoot}}
	engine, err := execution.NewExecutor(execution.Options{
		Scope:  "tenant-local-placement",
		Writer: applier,
	})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := engine.Apply(context.Background(), mutation.SemanticMutation{BaseRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	if applier.scope != "tenant-local-placement" || !receipt.NewRoot.Equals(newRoot) {
		t.Fatalf("scope/receipt = %q/%s", applier.scope, receipt.NewRoot)
	}
}

func TestExecutorReportsMissingReadCapability(t *testing.T) {
	engine, err := execution.NewExecutor(execution.Options{
		Scope:  "write-only",
		Writer: &fakeWriter{},
	})
	if err != nil {
		t.Fatal(err)
	}
	query, err := malt.MapKeyQuery("profile/name")
	if err != nil {
		t.Fatal(err)
	}
	_, err = engine.Read(context.Background(), malt.ReadRequest{Root: testCID(t, "root"), Query: query})
	if !errors.Is(err, execution.ErrCapabilityUnavailable) {
		t.Fatalf("Read error = %v, want ErrCapabilityUnavailable", err)
	}
}

func TestExecutorReadMapMapsSemanticAbsenceToFacadeError(t *testing.T) {
	query, err := malt.MapKeyQuery("missing")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := execution.NewExecutor(execution.Options{
		Scope: "missing-map",
		Maps:  errorMaps{err: fmt.Errorf("radix lookup: %w", mapping.ErrPathNotFound)},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = engine.Read(context.Background(), malt.ReadRequest{Root: testCID(t, "missing-root"), Query: query})
	if !errors.Is(err, malt.ErrQueryNotFound) {
		t.Fatalf("Read error = %v, want ErrQueryNotFound", err)
	}
	if !malt.IsQueryNotFound(err) {
		t.Fatalf("IsQueryNotFound(%v) = false", err)
	}
	if !errors.Is(err, mapping.ErrPathNotFound) {
		t.Fatalf("Read error = %v, want semantic not-found cause", err)
	}
}

func TestExecutorReadMapPreservesExecutionError(t *testing.T) {
	query, err := malt.MapKeyQuery("profile/name")
	if err != nil {
		t.Fatal(err)
	}
	executionErr := errors.New("map backend unavailable")
	engine, err := execution.NewExecutor(execution.Options{
		Scope: "failed-map",
		Maps:  errorMaps{err: executionErr},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = engine.Read(context.Background(), malt.ReadRequest{Root: testCID(t, "failed-root"), Query: query})
	if err != executionErr {
		t.Fatalf("Read error = %v, want original execution error %v", err, executionErr)
	}
	if malt.IsQueryNotFound(err) {
		t.Fatalf("IsQueryNotFound(%v) = true", err)
	}
}

func TestVerifyReadRejectsCrossKindProof(t *testing.T) {
	root := testCID(t, "cross-kind-root")
	target := testCID(t, "cross-kind-target")
	index := uint64(1)
	length := uint64(2)
	req := malt.ReadRequest{Root: root, Query: malt.ListIndexQuery(index)}
	result := malt.ReadResult{
		Target: target,
		ProofList: prooflist.ProofList{
			Root:  root,
			Query: req.Query.String(),
			Steps: []prooflist.Step{{
				Kind:            prooflist.KindMapStep,
				From:            root,
				Path:            req.Query.String(),
				Index:           &index,
				Length:          &length,
				Target:          target,
				EvidenceKind:    "structure",
				EvidenceBackend: "map",
				Proof:           []byte("valid-map-proof"),
			}},
		},
	}
	if err := malt.VerifyRead(context.Background(), req, result, acceptingVerifier{}); err == nil {
		t.Fatal("VerifyRead accepted a map proof for a list-index query")
	}
}

type acceptingVerifier struct{}

func (acceptingVerifier) VerifyProofList(context.Context, prooflist.ProofList) (bool, error) {
	return true, nil
}

type fakePathResolver struct {
	request malt.ResolveRequest
	result  malt.ResolveResult
	err     error
}

func (r *fakePathResolver) Resolve(_ context.Context, request malt.ResolveRequest) (malt.ResolveResult, error) {
	r.request = request
	return r.result, r.err
}

type fakeWriter struct {
	scope   string
	receipt mutation.WriteReceipt
}

func (w *fakeWriter) Apply(_ context.Context, scope string, _ mutation.SemanticMutation) (mutation.WriteReceipt, error) {
	w.scope = scope
	return w.receipt, nil
}

type fakeMaps struct {
	root   cid.Cid
	key    arcset.Path
	target cid.Cid
	proof  structure.Proof
	scope  string
}

type fakeAbsentMaps struct {
	root  cid.Cid
	key   arcset.Path
	proof structure.Proof
	scope string
}

func (m *fakeAbsentMaps) Prove(_ context.Context, scope string, root cid.Cid, key arcset.Path) (mapping.Binding, structure.Proof, error) {
	m.scope = scope
	if !root.Equals(m.root) || key != m.key {
		return mapping.Binding{}, nil, arcset.ErrNotFound
	}
	return mapping.Binding{Present: false}, append(structure.Proof(nil), m.proof...), nil
}

type errorMaps struct {
	err error
}

func (m errorMaps) Prove(context.Context, string, cid.Cid, arcset.Path) (mapping.Binding, structure.Proof, error) {
	return mapping.Binding{}, nil, m.err
}

func (m *fakeMaps) Prove(_ context.Context, scope string, root cid.Cid, key arcset.Path) (mapping.Binding, structure.Proof, error) {
	m.scope = scope
	if !root.Equals(m.root) || key != m.key {
		return mapping.Binding{}, nil, arcset.ErrNotFound
	}
	return mapping.Binding{Value: m.target, Present: true}, append(structure.Proof(nil), m.proof...), nil
}

type fakeLists struct {
	root   cid.Cid
	target cid.Cid
	length uint64
	proof  structure.Proof
}

func (l fakeLists) Prove(_ context.Context, _ string, root cid.Cid, _ uint64) (list.Query, structure.Proof, error) {
	if !root.Equals(l.root) {
		return list.Query{}, nil, arcset.ErrNotFound
	}
	return list.Query{Key: l.target, Length: l.length}, append(structure.Proof(nil), l.proof...), nil
}

type fakeMeasuredLists struct {
	root   cid.Cid
	result list.RangeResult
	proof  structure.Proof
}

func (l fakeMeasuredLists) Prove(context.Context, string, cid.Cid, uint64) (list.Query, structure.Proof, error) {
	return list.Query{}, nil, errors.New("index proof not implemented")
}

func (l fakeMeasuredLists) ProveRange(_ context.Context, _ string, root cid.Cid, _ uint64, _ *uint64) (list.RangeResult, structure.Proof, error) {
	if !root.Equals(l.root) {
		return list.RangeResult{}, nil, arcset.ErrNotFound
	}
	return l.result, append(structure.Proof(nil), l.proof...), nil
}

func testCID(t *testing.T, seed string) cid.Cid {
	t.Helper()
	hash, err := mh.Sum([]byte(seed), mh.SHA2_256, -1)
	if err != nil {
		t.Fatal(err)
	}
	return cid.NewCidV1(cid.Raw, hash)
}

var (
	_ malt.Resolver                = (*execution.Executor)(nil)
	_ malt.Reader                  = (*execution.Executor)(nil)
	_ malt.Resolver                = (*fakePathResolver)(nil)
	_ execution.MapReader          = (*fakeMaps)(nil)
	_ execution.ListReader         = fakeLists{}
	_ execution.MeasuredListReader = fakeMeasuredLists{}
	_ execution.MutationApplier    = (*fakeWriter)(nil)
)

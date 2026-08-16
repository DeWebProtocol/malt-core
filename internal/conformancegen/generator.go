// Package conformancegen deterministically produces the checked-in portable
// resolve/read verification vectors from the reference runtime.
package conformancegen

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"

	malt "github.com/dewebprotocol/malt-core"
	"github.com/dewebprotocol/malt-core/auth/arcset"
	materialmemory "github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
	"github.com/dewebprotocol/malt-core/auth/commitment/kzg"
	"github.com/dewebprotocol/malt-core/auth/proof/prooflist"
	"github.com/dewebprotocol/malt-core/auth/semantic/list"
	"github.com/dewebprotocol/malt-core/conformance"
	"github.com/dewebprotocol/malt-core/execution"
	runtimegraph "github.com/dewebprotocol/malt-core/graph/runtime"
	"github.com/dewebprotocol/malt-core/protocol"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

type backendFixture struct {
	name      string
	mapRoot   cid.Cid
	positives map[string]conformance.Vector
	vectors   []conformance.Vector
}

type fixedListCommitter interface {
	CommitFixed(context.Context, string, []cid.Cid, uint64, uint64) (cid.Cid, error)
}

// Generate builds and serializes the canonical corpus. Map iteration is never
// allowed to determine output order; vectors are sorted by stable ID.
func Generate() ([]byte, error) {
	identity, err := identityVector()
	if err != nil {
		return nil, err
	}

	kzgScheme, err := kzg.NewScheme()
	if err != nil {
		return nil, fmt.Errorf("create KZG scheme: %w", err)
	}
	kzgFixture, err := generateBackend(conformance.BackendKZG, kzgScheme)
	if err != nil {
		return nil, err
	}

	ipaScheme, err := ipa.NewScheme()
	if err != nil {
		return nil, fmt.Errorf("create IPA scheme: %w", err)
	}
	ipaFixture, err := generateBackend(conformance.BackendIPA, ipaScheme)
	if err != nil {
		return nil, err
	}

	vectors := []conformance.Vector{identity}
	vectors = append(vectors, kzgFixture.vectors...)
	vectors = append(vectors, ipaFixture.vectors...)

	kzgOnIPA, err := crossBackendVector(kzgFixture.positives["read-map-key"], ipaFixture.mapRoot, conformance.BackendIPA, conformance.BackendKZG)
	if err != nil {
		return nil, err
	}
	ipaOnKZG, err := crossBackendVector(ipaFixture.positives["read-map-key"], kzgFixture.mapRoot, conformance.BackendKZG, conformance.BackendIPA)
	if err != nil {
		return nil, err
	}
	vectors = append(vectors, kzgOnIPA, ipaOnKZG)

	slices.SortFunc(vectors, func(a, b conformance.Vector) int {
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})

	corpus := conformance.Corpus{SchemaVersion: conformance.ResolveReadV2, Vectors: vectors}
	if err := corpus.Validate(); err != nil {
		return nil, fmt.Errorf("validate generated corpus: %w", err)
	}
	data, err := json.MarshalIndent(corpus, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal generated corpus: %w", err)
	}
	return append(data, '\n'), nil
}

func identityVector() (conformance.Vector, error) {
	root, err := rawCID("resolve-identity-root")
	if err != nil {
		return conformance.Vector{}, err
	}
	request := malt.ResolveRequest{Root: root, Segments: []string{}}
	result := malt.ResolveResult{
		Target: root,
		ProofList: prooflist.ProofList{
			Root:  root,
			Query: "",
			Steps: []prooflist.Step{},
		},
	}
	verification, err := portableResolve(request, result)
	if err != nil {
		return conformance.Vector{}, err
	}
	return vector("resolve.identity.accept", conformance.OperationResolve, conformance.BackendNone, "identity", verification, true)
}

func generateBackend(name string, scheme commitment.IndexCommitment) (*backendFixture, error) {
	ctx := context.Background()

	mapScope := "conformance-v2-" + name + "-map"
	mapGraph, err := newGraph(mapScope, scheme)
	if err != nil {
		return nil, err
	}
	payload, err := rawCID("payload")
	if err != nil {
		return nil, err
	}
	leaf, err := rawCID("leaf")
	if err != nil {
		return nil, err
	}
	profileName, err := rawCID("profile-name")
	if err != nil {
		return nil, err
	}

	childRoot, err := createMap(ctx, mapGraph, map[string]cid.Cid{
		"@payload": payload,
		"leaf":     leaf,
	})
	if err != nil {
		return nil, fmt.Errorf("%s child map: %w", name, err)
	}
	mapRoot, err := createMap(ctx, mapGraph, map[string]cid.Cid{
		"@payload":     payload,
		"docs":         childRoot,
		"profile/name": profileName,
	})
	if err != nil {
		return nil, fmt.Errorf("%s root map: %w", name, err)
	}
	otherRoot, err := createMap(ctx, mapGraph, map[string]cid.Cid{
		"other": leaf,
	})
	if err != nil {
		return nil, fmt.Errorf("%s alternate map: %w", name, err)
	}
	mapExecutor, err := execution.NewExecutor(execution.Options{
		Scope:    mapScope,
		Resolver: mapGraph,
		Maps:     mapGraph.Semantic(),
	})
	if err != nil {
		return nil, err
	}

	indexScope := "conformance-v1-" + name + "-list-index"
	indexGraph, err := newGraph(indexScope, scheme)
	if err != nil {
		return nil, err
	}
	listValues, err := rawCIDs("list", 3)
	if err != nil {
		return nil, err
	}
	listRoot, err := indexGraph.ListSemantic().Commit(ctx, indexScope, list.NewViewFromSlice(listValues))
	if err != nil {
		return nil, fmt.Errorf("%s list commit: %w", name, err)
	}
	indexExecutor, err := execution.NewExecutor(execution.Options{Scope: indexScope, Lists: indexGraph.ListSemantic()})
	if err != nil {
		return nil, err
	}

	rangeScope := "conformance-v1-" + name + "-list-range"
	rangeGraph, err := newGraph(rangeScope, scheme)
	if err != nil {
		return nil, err
	}
	chunks, err := rawCIDs("chunk", 3)
	if err != nil {
		return nil, err
	}
	fixed, ok := rangeGraph.ListSemantic().(fixedListCommitter)
	if !ok {
		return nil, fmt.Errorf("%s list semantics do not support fixed-width ranges", name)
	}
	rangeRoot, err := fixed.CommitFixed(ctx, rangeScope, chunks, 8, 20)
	if err != nil {
		return nil, fmt.Errorf("%s fixed list commit: %w", name, err)
	}
	rangeExecutor, err := execution.NewExecutor(execution.Options{Scope: rangeScope, Lists: rangeGraph.ListSemantic()})
	if err != nil {
		return nil, err
	}

	fixture := &backendFixture{name: name, mapRoot: mapRoot, positives: map[string]conformance.Vector{}}
	addPositive := func(key, id, operation, category string, verification any) error {
		entry, err := vector(id, operation, name, category, verification, true)
		if err != nil {
			return err
		}
		fixture.positives[key] = entry
		fixture.vectors = append(fixture.vectors, entry)
		return nil
	}

	mapKeyResolve, err := executeResolve(ctx, mapExecutor, malt.ResolveRequest{Root: mapRoot, Segments: []string{"profile", "name"}})
	if err != nil {
		return nil, err
	}
	if err := addPositive("resolve-map-key", "resolve."+name+".map-key.accept", conformance.OperationResolve, "map_key", mapKeyResolve); err != nil {
		return nil, err
	}
	multihop, err := executeResolve(ctx, mapExecutor, malt.ResolveRequest{Root: mapRoot, Segments: []string{"docs", "leaf"}})
	if err != nil {
		return nil, err
	}
	if err := addPositive("resolve-multihop", "resolve."+name+".multihop.accept", conformance.OperationResolve, "multihop", multihop); err != nil {
		return nil, err
	}
	payloadResolve, err := executeResolve(ctx, mapExecutor, malt.ResolveRequest{Root: mapRoot, Segments: []string{"docs", "@payload"}})
	if err != nil {
		return nil, err
	}
	if err := addPositive("resolve-payload", "resolve."+name+".payload.accept", conformance.OperationResolve, "payload", payloadResolve); err != nil {
		return nil, err
	}

	mapQuery, err := malt.MapKeyQuery("profile/name")
	if err != nil {
		return nil, err
	}
	mapRead, err := executeRead(ctx, mapExecutor, malt.ReadRequest{Root: mapRoot, Query: mapQuery})
	if err != nil {
		return nil, err
	}
	if err := addPositive("read-map-key", "read."+name+".map-key.accept", conformance.OperationRead, "map_key", mapRead); err != nil {
		return nil, err
	}
	payloadQuery, err := malt.MapKeyQuery("@payload")
	if err != nil {
		return nil, err
	}
	payloadRead, err := executeRead(ctx, mapExecutor, malt.ReadRequest{Root: mapRoot, Query: payloadQuery})
	if err != nil {
		return nil, err
	}
	if err := addPositive("read-payload", "read."+name+".payload.accept", conformance.OperationRead, "payload", payloadRead); err != nil {
		return nil, err
	}
	indexRead, err := executeRead(ctx, indexExecutor, malt.ReadRequest{Root: listRoot, Query: malt.ListIndexQuery(1)})
	if err != nil {
		return nil, err
	}
	if err := addPositive("read-list-index", "read."+name+".list-index.accept", conformance.OperationRead, "list_index", indexRead); err != nil {
		return nil, err
	}
	end := uint64(18)
	boundedQuery, err := malt.ListRangeQuery(2, &end)
	if err != nil {
		return nil, err
	}
	boundedRange, err := executeRead(ctx, rangeExecutor, malt.ReadRequest{Root: rangeRoot, Query: boundedQuery})
	if err != nil {
		return nil, err
	}
	if err := addPositive("read-list-range", "read."+name+".list-range-bounded.accept", conformance.OperationRead, "list_range", boundedRange); err != nil {
		return nil, err
	}
	eofQuery, err := malt.ListRangeQuery(8, nil)
	if err != nil {
		return nil, err
	}
	eofRange, err := executeRead(ctx, rangeExecutor, malt.ReadRequest{Root: rangeRoot, Query: eofQuery})
	if err != nil {
		return nil, err
	}
	if err := addPositive("read-list-range-eof", "read."+name+".list-range-eof.accept", conformance.OperationRead, "list_range", eofRange); err != nil {
		return nil, err
	}

	negatives, err := negativeVectors(name, fixture.positives, otherRoot)
	if err != nil {
		return nil, err
	}
	fixture.vectors = append(fixture.vectors, negatives...)
	return fixture, nil
}

func negativeVectors(name string, positives map[string]conformance.Vector, otherRoot cid.Cid) ([]conformance.Vector, error) {
	var vectors []conformance.Vector
	appendVector := func(value conformance.Vector, err error) error {
		if err != nil {
			return err
		}
		vectors = append(vectors, value)
		return nil
	}

	resolveBase := positives["resolve-multihop"]
	if err := appendVector(tamperResolveEvidence(resolveBase, "resolve."+name+".evidence-tamper.reject", name)); err != nil {
		return nil, err
	}
	if err := appendVector(crossRootResolve(resolveBase, otherRoot, "resolve."+name+".cross-root.reject", name)); err != nil {
		return nil, err
	}
	if err := appendVector(malformedBase64(resolveBase, "resolve."+name+".malformed-base64.reject", name)); err != nil {
		return nil, err
	}
	if err := appendVector(truncatedEvidence(resolveBase, "resolve."+name+".truncated-evidence.reject", name)); err != nil {
		return nil, err
	}
	if err := appendVector(missingEvidence(resolveBase, "resolve."+name+".missing-evidence.reject", name)); err != nil {
		return nil, err
	}
	if err := appendVector(unknownVerificationField(resolveBase, "resolve."+name+".unknown-field.reject", name)); err != nil {
		return nil, err
	}

	readBase := positives["read-map-key"]
	if err := appendVector(tamperReadProof(readBase, "read."+name+".proof-tamper.reject", name)); err != nil {
		return nil, err
	}
	if err := appendVector(tamperReadTarget(readBase, "read."+name+".target-tamper.reject", name)); err != nil {
		return nil, err
	}
	if err := appendVector(crossRootRead(readBase, otherRoot, "read."+name+".cross-root.reject", name)); err != nil {
		return nil, err
	}
	if err := appendVector(crossKindRead(readBase, "read."+name+".cross-kind.reject", name)); err != nil {
		return nil, err
	}
	if err := appendVector(malformedBase64(readBase, "read."+name+".malformed-base64.reject", name)); err != nil {
		return nil, err
	}
	if err := appendVector(truncatedEvidence(readBase, "read."+name+".truncated-evidence.reject", name)); err != nil {
		return nil, err
	}
	if err := appendVector(missingEvidence(readBase, "read."+name+".missing-evidence.reject", name)); err != nil {
		return nil, err
	}
	if err := appendVector(unknownVerificationField(readBase, "read."+name+".unknown-field.reject", name)); err != nil {
		return nil, err
	}
	if err := appendVector(tamperRangeSegments(positives["read-list-range"], "read."+name+".range-segments-tamper.reject", name)); err != nil {
		return nil, err
	}
	return vectors, nil
}

func newGraph(scope string, scheme commitment.IndexCommitment) (*runtimegraph.RuntimeGraph, error) {
	graph, err := runtimegraph.NewGraph(scope, materialmemory.New(true), runtimegraph.WithNamespace(scope), runtimegraph.WithCommitmentScheme(scheme))
	if err != nil {
		return nil, fmt.Errorf("create graph %q: %w", scope, err)
	}
	return graph, nil
}

func createMap(ctx context.Context, graph *runtimegraph.RuntimeGraph, entries map[string]cid.Cid) (cid.Cid, error) {
	arcs, err := arcset.NewArcSet(entries)
	if err != nil {
		return cid.Undef, err
	}
	return graph.StructureCreator().CreateStructure(ctx, graph.Namespace(), arcs)
}

func executeResolve(ctx context.Context, executor *execution.Executor, request malt.ResolveRequest) (protocol.ResolveVerification, error) {
	result, err := executor.Resolve(ctx, request)
	if err != nil {
		return protocol.ResolveVerification{}, fmt.Errorf("execute resolve: %w", err)
	}
	return portableResolve(request, result)
}

func portableResolve(request malt.ResolveRequest, result malt.ResolveResult) (protocol.ResolveVerification, error) {
	portableRequest, err := protocol.NewResolveRequest(request)
	if err != nil {
		return protocol.ResolveVerification{}, err
	}
	portableResult, err := protocol.NewResolveResult(result)
	if err != nil {
		return protocol.ResolveVerification{}, err
	}
	return protocol.ResolveVerification{Request: portableRequest, Result: portableResult}, nil
}

func executeRead(ctx context.Context, executor *execution.Executor, request malt.ReadRequest) (protocol.ReadVerification, error) {
	result, err := executor.Read(ctx, request)
	if err != nil {
		return protocol.ReadVerification{}, fmt.Errorf("execute read: %w", err)
	}
	portableRequest, err := protocol.NewReadRequest(request)
	if err != nil {
		return protocol.ReadVerification{}, err
	}
	portableResult, err := protocol.NewReadResult(result)
	if err != nil {
		return protocol.ReadVerification{}, err
	}
	return protocol.ReadVerification{Request: portableRequest, Result: portableResult}, nil
}

func vector(id, operation, backend, category string, verification any, valid bool) (conformance.Vector, error) {
	raw, err := json.Marshal(verification)
	if err != nil {
		return conformance.Vector{}, fmt.Errorf("marshal vector %q verification: %w", id, err)
	}
	return conformance.Vector{
		ID:           id,
		Operation:    operation,
		Backend:      backend,
		Category:     category,
		Verification: raw,
		Expected:     conformance.Expected{Valid: valid},
	}, nil
}

func tamperResolveEvidence(base conformance.Vector, id, backend string) (conformance.Vector, error) {
	var value protocol.ResolveVerification
	if err := json.Unmarshal(base.Verification, &value); err != nil {
		return conformance.Vector{}, err
	}
	if len(value.Result.ProofList.Steps) == 0 || len(value.Result.ProofList.Steps[0].Evidence) == 0 {
		return conformance.Vector{}, fmt.Errorf("resolve tamper base has no evidence")
	}
	tampered, err := tamperSemanticProof(value.Result.ProofList.Steps[0].Evidence)
	if err != nil {
		return conformance.Vector{}, fmt.Errorf("tamper resolve evidence: %w", err)
	}
	value.Result.ProofList.Steps[0].Evidence = tampered
	return vector(id, conformance.OperationResolve, backend, "tamper", value, false)
}

func crossRootResolve(base conformance.Vector, otherRoot cid.Cid, id, backend string) (conformance.Vector, error) {
	var value protocol.ResolveVerification
	if err := json.Unmarshal(base.Verification, &value); err != nil {
		return conformance.Vector{}, err
	}
	value.Request.Root = otherRoot.String()
	value.Result.ProofList.Root = otherRoot
	value.Result.ProofList.Steps[0].From = otherRoot
	return vector(id, conformance.OperationResolve, backend, "cross_root", value, false)
}

func tamperReadProof(base conformance.Vector, id, backend string) (conformance.Vector, error) {
	var value protocol.ReadVerification
	if err := json.Unmarshal(base.Verification, &value); err != nil {
		return conformance.Vector{}, err
	}
	if len(value.Result.ProofList.Steps) == 0 || len(value.Result.ProofList.Steps[0].Proof) == 0 {
		return conformance.Vector{}, fmt.Errorf("read tamper base has no proof")
	}
	tampered, err := tamperSemanticProof(value.Result.ProofList.Steps[0].Proof)
	if err != nil {
		return conformance.Vector{}, fmt.Errorf("tamper read proof: %w", err)
	}
	value.Result.ProofList.Steps[0].Proof = tampered
	return vector(id, conformance.OperationRead, backend, "tamper", value, false)
}

func tamperReadTarget(base conformance.Vector, id, backend string) (conformance.Vector, error) {
	var value protocol.ReadVerification
	if err := json.Unmarshal(base.Verification, &value); err != nil {
		return conformance.Vector{}, err
	}
	forged, err := rawCID("forged-read-target")
	if err != nil {
		return conformance.Vector{}, err
	}
	value.Result.Target = forged.String()
	value.Result.ProofList.Steps[0].Target = forged
	return vector(id, conformance.OperationRead, backend, "tamper", value, false)
}

func crossRootRead(base conformance.Vector, otherRoot cid.Cid, id, backend string) (conformance.Vector, error) {
	var value protocol.ReadVerification
	if err := json.Unmarshal(base.Verification, &value); err != nil {
		return conformance.Vector{}, err
	}
	value.Request.Root = otherRoot.String()
	value.Result.ProofList.Root = otherRoot
	value.Result.ProofList.Steps[0].From = otherRoot
	return vector(id, conformance.OperationRead, backend, "cross_root", value, false)
}

func crossKindRead(base conformance.Vector, id, backend string) (conformance.Vector, error) {
	var value protocol.ReadVerification
	if err := json.Unmarshal(base.Verification, &value); err != nil {
		return conformance.Vector{}, err
	}
	index := uint64(0)
	value.Request.Query = protocol.Query{Kind: protocol.QueryListIndex, Index: &index}
	value.Result.ProofList.Query = "list:0"
	return vector(id, conformance.OperationRead, backend, "cross_kind", value, false)
}

func tamperRangeSegments(base conformance.Vector, id, backend string) (conformance.Vector, error) {
	var value protocol.ReadVerification
	if err := json.Unmarshal(base.Verification, &value); err != nil {
		return conformance.Vector{}, err
	}
	if len(value.Result.RangeSegments) < 2 {
		return conformance.Vector{}, fmt.Errorf("range tamper base has fewer than two segments")
	}
	value.Result.RangeSegments[0], value.Result.RangeSegments[1] = value.Result.RangeSegments[1], value.Result.RangeSegments[0]
	return vector(id, conformance.OperationRead, backend, "tamper", value, false)
}

func malformedBase64(base conformance.Vector, id, backend string) (conformance.Vector, error) {
	value, err := rawObject(base.Verification)
	if err != nil {
		return conformance.Vector{}, err
	}
	result, err := objectField(value, "result")
	if err != nil {
		return conformance.Vector{}, err
	}
	proofList, err := objectField(result, "prooflist")
	if err != nil {
		return conformance.Vector{}, err
	}
	steps, ok := proofList["steps"].([]any)
	if !ok || len(steps) == 0 {
		return conformance.Vector{}, fmt.Errorf("vector %q has no proof steps", base.ID)
	}
	step, ok := steps[0].(map[string]any)
	if !ok {
		return conformance.Vector{}, fmt.Errorf("vector %q first proof step is not an object", base.ID)
	}
	field := "proof"
	if base.Operation == conformance.OperationResolve {
		field = "evidence"
	}
	step[field] = "not-base64%%%"
	return vector(id, base.Operation, backend, "malformed_evidence", value, false)
}

func unknownVerificationField(base conformance.Vector, id, backend string) (conformance.Vector, error) {
	value, err := rawObject(base.Verification)
	if err != nil {
		return conformance.Vector{}, err
	}
	value["unexpected"] = true
	return vector(id, base.Operation, backend, "strict_json", value, false)
}

func truncatedEvidence(base conformance.Vector, id, backend string) (conformance.Vector, error) {
	switch base.Operation {
	case conformance.OperationResolve:
		var value protocol.ResolveVerification
		if err := json.Unmarshal(base.Verification, &value); err != nil {
			return conformance.Vector{}, err
		}
		truncated, err := truncateSemanticProof(value.Result.ProofList.Steps[0].Evidence)
		if err != nil {
			return conformance.Vector{}, err
		}
		value.Result.ProofList.Steps[0].Evidence = truncated
		return vector(id, base.Operation, backend, "malformed_evidence", value, false)
	case conformance.OperationRead:
		var value protocol.ReadVerification
		if err := json.Unmarshal(base.Verification, &value); err != nil {
			return conformance.Vector{}, err
		}
		truncated, err := truncateSemanticProof(value.Result.ProofList.Steps[0].Proof)
		if err != nil {
			return conformance.Vector{}, err
		}
		value.Result.ProofList.Steps[0].Proof = truncated
		return vector(id, base.Operation, backend, "malformed_evidence", value, false)
	default:
		return conformance.Vector{}, fmt.Errorf("unsupported operation %q", base.Operation)
	}
}

func missingEvidence(base conformance.Vector, id, backend string) (conformance.Vector, error) {
	switch base.Operation {
	case conformance.OperationResolve:
		var value protocol.ResolveVerification
		if err := json.Unmarshal(base.Verification, &value); err != nil {
			return conformance.Vector{}, err
		}
		value.Result.ProofList.Steps[0].Evidence = nil
		return vector(id, base.Operation, backend, "malformed_evidence", value, false)
	case conformance.OperationRead:
		var value protocol.ReadVerification
		if err := json.Unmarshal(base.Verification, &value); err != nil {
			return conformance.Vector{}, err
		}
		value.Result.ProofList.Steps[0].Proof = nil
		return vector(id, base.Operation, backend, "malformed_evidence", value, false)
	default:
		return conformance.Vector{}, fmt.Errorf("unsupported operation %q", base.Operation)
	}
}

func crossBackendVector(base conformance.Vector, destinationRoot cid.Cid, destinationBackend, sourceBackend string) (conformance.Vector, error) {
	var value protocol.ReadVerification
	if err := json.Unmarshal(base.Verification, &value); err != nil {
		return conformance.Vector{}, err
	}
	value.Request.Root = destinationRoot.String()
	value.Result.ProofList.Root = destinationRoot
	value.Result.ProofList.Steps[0].From = destinationRoot
	id := "read." + destinationBackend + ".cross-backend-" + sourceBackend + "-evidence.reject"
	return vector(id, conformance.OperationRead, destinationBackend, "cross_backend", value, false)
}

func rawObject(data []byte) (map[string]any, error) {
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		return nil, err
	}
	return value, nil
}

func objectField(value map[string]any, name string) (map[string]any, error) {
	field, ok := value[name].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("field %q is not an object", name)
	}
	return field, nil
}

// tamperSemanticProof preserves the radix proof JSON envelope and the
// primitive proof framing. Built-in KZG and IPA index proofs both end in the
// authenticated uint32 index, so changing its final byte remains decodable but
// makes verification reject the proof/query binding.
func tamperSemanticProof(proof []byte) ([]byte, error) {
	return mutateSemanticProof(proof, func(primitive []byte) ([]byte, error) {
		if len(primitive) < 4 {
			return nil, fmt.Errorf("primitive proof is too short")
		}
		primitive = slices.Clone(primitive)
		primitive[len(primitive)-1] ^= 0x01
		return primitive, nil
	})
}

func truncateSemanticProof(proof []byte) ([]byte, error) {
	return mutateSemanticProof(proof, func(primitive []byte) ([]byte, error) {
		if len(primitive) < 5 {
			return nil, fmt.Errorf("primitive proof is too short to truncate")
		}
		return slices.Clone(primitive[:len(primitive)-1]), nil
	})
}

func mutateSemanticProof(proof []byte, mutate func([]byte) ([]byte, error)) ([]byte, error) {
	envelope, err := rawObject(proof)
	if err != nil {
		return nil, fmt.Errorf("decode semantic proof envelope: %w", err)
	}
	steps, ok := envelope["steps"].([]any)
	if !ok || len(steps) == 0 {
		return nil, fmt.Errorf("semantic proof envelope has no steps")
	}
	step, ok := steps[0].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("semantic proof step is not an object")
	}
	encoded, ok := step["proof"].(string)
	if !ok {
		return nil, fmt.Errorf("semantic proof step has no encoded proof")
	}
	primitive, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode primitive proof: %w", err)
	}
	primitive, err = mutate(primitive)
	if err != nil {
		return nil, err
	}
	step["proof"] = base64.StdEncoding.EncodeToString(primitive)
	tampered, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("encode semantic proof envelope: %w", err)
	}
	return tampered, nil
}

func rawCIDs(prefix string, count int) ([]cid.Cid, error) {
	out := make([]cid.Cid, count)
	for i := range out {
		value, err := rawCID(fmt.Sprintf("%s-%d", prefix, i))
		if err != nil {
			return nil, err
		}
		out[i] = value
	}
	return out, nil
}

func rawCID(seed string) (cid.Cid, error) {
	digest, err := mh.Sum([]byte("malt-conformance-v1:"+seed), mh.SHA2_256, -1)
	if err != nil {
		return cid.Undef, err
	}
	return cid.NewCidV1(cid.Raw, digest), nil
}

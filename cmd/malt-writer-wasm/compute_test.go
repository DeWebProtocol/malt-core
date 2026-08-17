package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	materializermemory "github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
	"github.com/dewebprotocol/malt-core/auth/commitment/kzg"
	"github.com/dewebprotocol/malt-core/auth/semantic/mapping"
	mappingradix "github.com/dewebprotocol/malt-core/auth/semantic/mapping/radix"
	"github.com/dewebprotocol/malt-core/mutation"
	"github.com/dewebprotocol/malt-core/protocol"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

func TestParseStartupBackend(t *testing.T) {
	for _, backend := range []string{"kzg", "ipa"} {
		t.Run(backend, func(t *testing.T) {
			got, err := parseStartupBackend([]string{backendArgumentPrefix + backend})
			if err != nil {
				t.Fatalf("parseStartupBackend failed: %v", err)
			}
			if got != backend {
				t.Fatalf("backend = %q, want %q", got, backend)
			}
		})
	}
	for _, args := range [][]string{
		nil,
		{"kzg"},
		{backendArgumentPrefix},
		{backendArgumentPrefix + "all"},
		{backendArgumentPrefix + "kzg", backendArgumentPrefix + "ipa"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			if backend, err := parseStartupBackend(args); err == nil {
				t.Fatalf("parseStartupBackend(%q) = %q, want error", args, backend)
			}
		})
	}
}

func TestComputerComputesCanonicalClientRootBundle(t *testing.T) {
	view, intent := computeFixture(t, maltcid.BackendKindKZG)
	wireView, err := protocol.NewUpdateView(view)
	if err != nil {
		t.Fatalf("NewUpdateView failed: %v", err)
	}
	wireIntent, err := protocol.NewSemanticIntent(view, intent)
	if err != nil {
		t.Fatalf("NewSemanticIntent failed: %v", err)
	}
	viewJSON, err := json.Marshal(wireView)
	if err != nil {
		t.Fatalf("marshal update view: %v", err)
	}
	intentJSON, err := json.Marshal(wireIntent)
	if err != nil {
		t.Fatalf("marshal semantic intent: %v", err)
	}

	writer, err := newComputer("kzg")
	if err != nil {
		t.Fatalf("newComputer failed: %v", err)
	}
	raw, err := writer.compute(t.Context(), "browser-operation-1", viewJSON, intentJSON)
	if err != nil {
		t.Fatalf("compute failed: %v", err)
	}
	response, err := protocol.DecodeWriterComputeResult(raw)
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Profile != protocol.WriterComputeResultProfile {
		t.Fatalf("profile = %q, want %q", response.Profile, protocol.WriterComputeResultProfile)
	}
	bundle, err := response.Bundle.Core()
	if err != nil {
		t.Fatalf("bundle Core failed: %v", err)
	}
	if bundle.Candidate.Equals(view.BaseRoot) {
		t.Fatal("client writer did not change the candidate root")
	}
	if maltcid.BackendKindOf(bundle.Candidate) != maltcid.BackendKindKZG {
		t.Fatalf("candidate backend = %q, want KZG", maltcid.BackendKindOf(bundle.Candidate))
	}
	if bundle.OperationID != "browser-operation-1" || len(bundle.Outputs) != 1 || len(bundle.PayloadCIDs) != 1 {
		t.Fatalf("unexpected bundle summary: operation=%q outputs=%d payloads=%d", bundle.OperationID, len(bundle.Outputs), len(bundle.PayloadCIDs))
	}
	next, err := response.NextView.Core()
	if err != nil {
		t.Fatalf("next view Core failed: %v", err)
	}
	if !next.BaseRoot.Equals(bundle.Candidate) {
		t.Fatalf("next base %s does not match candidate %s", next.BaseRoot, bundle.Candidate)
	}
	if response.Metrics.CommitmentUpdateNS == 0 || response.Metrics.TotalNS == 0 {
		t.Fatalf("writer metrics did not record local commitment work: %+v", response.Metrics)
	}
}

func TestComputerRejectsUnavailableBackendAndInvalidJSON(t *testing.T) {
	view, intent := computeFixture(t, maltcid.BackendKindKZG)
	wireView, err := protocol.NewUpdateView(view)
	if err != nil {
		t.Fatalf("NewUpdateView failed: %v", err)
	}
	wireIntent, err := protocol.NewSemanticIntent(view, intent)
	if err != nil {
		t.Fatalf("NewSemanticIntent failed: %v", err)
	}
	viewJSON, _ := json.Marshal(wireView)
	intentJSON, _ := json.Marshal(wireIntent)

	writer, err := newComputer("ipa")
	if err != nil {
		t.Fatalf("newComputer failed: %v", err)
	}
	if _, err := writer.compute(t.Context(), "browser-operation-2", viewJSON, intentJSON); err == nil {
		t.Fatal("IPA-only writer accepted a KZG update view")
	}
	if _, err := writer.compute(t.Context(), "browser-operation-3", []byte(`{}`), []byte(`{}`)); err == nil {
		t.Fatal("writer accepted invalid client-root JSON")
	}
}

func TestSessionComputerBootstrapCarriesBaseMaterialization(t *testing.T) {
	for _, backend := range []maltcid.BackendKind{maltcid.BackendKindKZG, maltcid.BackendKindIPA} {
		t.Run(string(backend), func(t *testing.T) {
			computer, err := newComputer(string(backend))
			if err != nil {
				t.Fatalf("newComputer: %v", err)
			}
			session, err := newSessionComputer(computer)
			if err != nil {
				t.Fatal(err)
			}
			viewJSON, err := session.bootstrap(t.Context())
			if err != nil {
				t.Fatalf("bootstrap: %v", err)
			}
			wireView, err := protocol.DecodeUpdateView(viewJSON)
			if err != nil {
				t.Fatalf("DecodeUpdateView: %v", err)
			}
			view, err := wireView.Core()
			if err != nil {
				t.Fatal(err)
			}
			payload := payloadCID(t, "bootstrap-payload-"+string(backend))
			after := arcset.NewCASTarget(payload)
			coordinate, err := arcset.NewMapCoordinate("first")
			if err != nil {
				t.Fatal(err)
			}
			intent := mutation.SemanticIntent{
				Profile: mutation.SemanticIntentProfile, BaseRoot: view.BaseRoot, TopOutputID: "root-output",
				Transitions: []mutation.IntentTransition{{
					ID: "root-output", ObjectID: "root", OldRoot: view.BaseRoot, Kind: arcset.KindMap, Backend: backend,
					Changes: []mutation.IntentChange{{Coordinate: coordinate, After: &after}},
				}},
			}
			wireIntent, err := protocol.NewSemanticIntent(view, intent)
			if err != nil {
				t.Fatalf("NewSemanticIntent: %v", err)
			}
			intentJSON, err := json.Marshal(wireIntent)
			if err != nil {
				t.Fatal(err)
			}
			const operationID = "bootstrap-first-write"
			if _, err := session.prepare(t.Context(), operationID, intentJSON); err != nil {
				t.Fatalf("prepare: %v", err)
			}
			resultJSON, err := session.getPreparedResult(operationID)
			if err != nil {
				t.Fatal(err)
			}
			result, err := protocol.DecodeWriterComputeResult(resultJSON)
			if err != nil {
				t.Fatalf("DecodeWriterComputeResult: %v", err)
			}
			if result.Materialization.Base == nil || result.Materialization.Base.Root != view.BaseRoot.String() {
				t.Fatalf("base materialization = %+v", result.Materialization.Base)
			}
			bundle, err := result.Bundle.Core()
			if err != nil {
				t.Fatal(err)
			}
			materialization, err := result.Materialization.Core(bundle)
			if err != nil {
				t.Fatalf("materialization Core: %v", err)
			}
			rootBound, ok := computer.schemes[backend].(mappingradix.RootBoundVerifier)
			if !ok {
				t.Fatal("writer backend does not support root-bound validation")
			}
			if err := mappingradix.ValidateMaterialization(t.Context(), rootBound, view.BaseRoot, mapping.NewViewFromPaths(nil), materialization.Base.Entries); err != nil {
				t.Fatalf("ValidateMaterialization: %v", err)
			}
		})
	}
}

func TestSessionComputerAdvancesOnlyAfterExactReceipt(t *testing.T) {
	view, intent := computeFixture(t, maltcid.BackendKindKZG)
	wireView, err := protocol.NewUpdateView(view)
	if err != nil {
		t.Fatalf("NewUpdateView failed: %v", err)
	}
	wireIntent, err := protocol.NewSemanticIntent(view, intent)
	if err != nil {
		t.Fatalf("NewSemanticIntent failed: %v", err)
	}
	viewJSON, _ := json.Marshal(wireView)
	intentJSON, _ := json.Marshal(wireIntent)
	computer, err := newComputer("kzg")
	if err != nil {
		t.Fatalf("newComputer failed: %v", err)
	}
	session, err := newSessionComputer(computer)
	if err != nil {
		t.Fatalf("newSessionComputer failed: %v", err)
	}
	loadedRoot, err := session.load(t.Context(), viewJSON)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if loadedRoot != view.BaseRoot.String() {
		t.Fatalf("loaded root = %s, want %s", loadedRoot, view.BaseRoot)
	}

	const operationID = "session-operation-1"
	preparedRoot, err := session.prepare(t.Context(), operationID, intentJSON)
	if err != nil {
		t.Fatalf("prepare failed: %v", err)
	}
	if _, err := session.prepare(t.Context(), operationID, intentJSON); err == nil {
		t.Fatal("session accepted a duplicate prepared operation")
	}
	raw, err := session.getPreparedResult(operationID)
	if err != nil {
		t.Fatalf("getPreparedResult failed: %v", err)
	}
	response, err := protocol.DecodeWriterComputeResult(raw)
	if err != nil {
		t.Fatalf("DecodeWriterComputeResult failed: %v", err)
	}
	if preparedRoot != response.Bundle.Candidate {
		t.Fatalf("prepared root = %s, result candidate = %s", preparedRoot, response.Bundle.Candidate)
	}
	bundle, err := response.Bundle.Core()
	if err != nil {
		t.Fatalf("bundle Core failed: %v", err)
	}
	bundleDigest, err := bundle.Digest()
	if err != nil {
		t.Fatalf("bundle Digest failed: %v", err)
	}
	receipt, err := protocol.NewMaterializationReceipt(mutation.MaterializationReceipt{
		Profile: mutation.MaterializationReceiptProfile, OperationID: operationID,
		BaseRoot: bundle.View.BaseRoot, Candidate: bundle.Candidate,
		BundleDigest: bundleDigest, DurableBoundary: "unit-memory-v1",
	}, bundle)
	if err != nil {
		t.Fatalf("NewMaterializationReceipt failed: %v", err)
	}
	badReceipt := receipt
	badReceipt.Candidate = view.BaseRoot.String()
	badReceiptJSON, _ := json.Marshal(badReceipt)
	if _, err := session.acceptReceipt(operationID, badReceiptJSON); err == nil {
		t.Fatal("session accepted a mismatched receipt")
	}
	if got := session.session.BaseRoot(); !got.Equals(view.BaseRoot) {
		t.Fatalf("base advanced after bad receipt: %s", got)
	}
	stillPrepared, err := session.getPreparedResult(operationID)
	if err != nil {
		t.Fatalf("getPreparedResult after rejected receipt failed: %v", err)
	}
	if !bytes.Equal(stillPrepared, raw) {
		t.Fatal("rejected receipt changed the prepared result")
	}
	stillPrepared[0] ^= 0xff
	unmodified, err := session.getPreparedResult(operationID)
	if err != nil {
		t.Fatalf("getPreparedResult after caller mutation failed: %v", err)
	}
	if !bytes.Equal(unmodified, raw) {
		t.Fatal("caller mutation changed the retained prepared result")
	}

	receiptJSON, _ := json.Marshal(receipt)
	acceptedRoot, err := session.acceptReceipt(operationID, receiptJSON)
	if err != nil {
		t.Fatalf("acceptReceipt failed: %v", err)
	}
	if acceptedRoot != bundle.Candidate.String() {
		t.Fatalf("accepted root = %s, want %s", acceptedRoot, bundle.Candidate)
	}
	if got := session.session.BaseRoot(); !got.Equals(bundle.Candidate) {
		t.Fatalf("retained base = %s, want %s", got, bundle.Candidate)
	}
	if _, err := session.getPreparedResult(operationID); err == nil {
		t.Fatal("accepted operation remained available as a prepared result")
	}
	fresh, err := newSessionComputer(computer)
	if err != nil {
		t.Fatal(err)
	}
	nextViewJSON, err := json.Marshal(response.NextView)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.load(t.Context(), nextViewJSON); err != nil {
		t.Fatal(err)
	}
	if got, want := session.store.EntryCount(), fresh.store.EntryCount(); got != want {
		t.Fatalf("accepted session retained %d entries, fresh accepted view retains %d", got, want)
	}
	if _, err := session.prepare(t.Context(), "stale-operation", intentJSON); err == nil {
		t.Fatal("session accepted an intent at the stale base")
	}
}

func TestSessionComputerRetainsLegacyWorkingRootsAcrossAcceptedOperations(t *testing.T) {
	for _, backend := range []maltcid.BackendKind{maltcid.BackendKindKZG, maltcid.BackendKindIPA} {
		t.Run(string(backend), func(t *testing.T) {
			ctx := context.Background()
			computer, err := newComputer(string(backend))
			if err != nil {
				t.Fatal(err)
			}
			legacyStore := materializermemory.New(true)
			legacyMap, err := mappingradix.NewMapForVersion(
				computer.schemes[backend], legacyStore, maltcid.LegacyMALTVersionID,
			)
			if err != nil {
				t.Fatal(err)
			}

			childOld := payloadCID(t, string(backend)+"-legacy-child-old")
			childNew := payloadCID(t, string(backend)+"-legacy-child-new")
			childRoot, err := legacyMap.Commit(ctx, "client-root/v1/child", mapping.NewViewFrom(map[string]cid.Cid{
				"value": childOld,
			}))
			if err != nil {
				t.Fatal(err)
			}
			childEntries, err := arcset.NewCanonicalArcSet(arcset.KindMap, []arcset.ArcEntry{{
				Coordinate: wasmMapCoordinate(t, "value"), Target: arcset.NewCASTarget(childOld),
			}})
			if err != nil {
				t.Fatal(err)
			}

			rootOld := payloadCID(t, string(backend)+"-legacy-root-old")
			rootNew := payloadCID(t, string(backend)+"-legacy-root-new")
			rootRoot, err := legacyMap.Commit(ctx, "client-root/v1/root", mapping.NewViewFrom(map[string]cid.Cid{
				"child": childRoot,
				"value": rootOld,
			}))
			if err != nil {
				t.Fatal(err)
			}
			rootEntries, err := arcset.NewCanonicalArcSet(arcset.KindMap, []arcset.ArcEntry{
				{Coordinate: wasmMapCoordinate(t, "child"), Target: arcset.NewMapTarget(childRoot)},
				{Coordinate: wasmMapCoordinate(t, "value"), Target: arcset.NewCASTarget(rootOld)},
			})
			if err != nil {
				t.Fatal(err)
			}
			view := mutation.UpdateView{
				Profile: mutation.UpdateViewProfile, StateProfile: mutation.StatefulCompleteVectorsProfile,
				BaseRoot: rootRoot, Bounds: mutation.UpdateViewBounds{MaxObjects: 4, MaxTotalEntries: 16, MaxDepth: 4},
				Objects: []mutation.UpdateObject{
					{ObjectID: "root", Root: rootRoot, Kind: arcset.KindMap, Entries: rootEntries},
					{ObjectID: "child", Root: childRoot, Kind: arcset.KindMap, Entries: childEntries},
				},
			}
			wireView, err := protocol.NewUpdateView(view)
			if err != nil {
				t.Fatal(err)
			}
			viewJSON, err := json.Marshal(wireView)
			if err != nil {
				t.Fatal(err)
			}
			session, err := newSessionComputer(computer)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := session.load(ctx, viewJSON); err != nil {
				t.Fatalf("load legacy view: %v", err)
			}
			workingRoots := session.session.WorkingRoots()
			childWorkingRoot := workingRoots["child"]
			if !childWorkingRoot.Defined() || maltcid.VersionIDOf(childWorkingRoot) != maltcid.MALTVersionID || childWorkingRoot.Equals(childRoot) {
				t.Fatalf("child working root = %s, want migrated current root distinct from %s", childWorkingRoot, childRoot)
			}
			workingRoots["child"] = cid.Undef
			if got := session.session.WorkingRoots()["child"]; !got.Equals(childWorkingRoot) {
				t.Fatal("caller mutation changed the session working-root projection")
			}

			beforeRoot, afterRoot := arcset.NewCASTarget(rootOld), arcset.NewCASTarget(rootNew)
			firstIntent := mutation.SemanticIntent{
				Profile: mutation.SemanticIntentProfile, BaseRoot: rootRoot, TopOutputID: "root-output-1",
				Transitions: []mutation.IntentTransition{{
					ID: "root-output-1", ObjectID: "root", OldRoot: rootRoot,
					Kind: arcset.KindMap, Backend: backend,
					Changes: []mutation.IntentChange{{
						Coordinate: wasmMapCoordinate(t, "value"), Before: &beforeRoot, After: &afterRoot,
					}},
				}},
			}
			firstCandidate := prepareAndAcceptSessionIntent(t, session, "legacy-root-first", firstIntent)
			if got := wasmObjectRootByID(t, session.view, "child"); !got.Equals(childRoot) {
				t.Fatalf("first next view child root = %s, want legacy root %s", got, childRoot)
			}

			beforeChild := arcset.NewMapTarget(childRoot)
			beforeChildValue, afterChildValue := arcset.NewCASTarget(childOld), arcset.NewCASTarget(childNew)
			secondIntent := mutation.SemanticIntent{
				Profile: mutation.SemanticIntentProfile, BaseRoot: firstCandidate, TopOutputID: "root-output-2",
				Transitions: []mutation.IntentTransition{
					{
						ID: "root-output-2", ObjectID: "root", OldRoot: firstCandidate,
						Kind: arcset.KindMap, Backend: backend,
						Changes: []mutation.IntentChange{{
							Coordinate: wasmMapCoordinate(t, "child"), Before: &beforeChild,
							OutputID: "child-output-2", OutputKind: arcset.TargetKindMap,
						}},
					},
					{
						ID: "child-output-2", ObjectID: "child", OldRoot: childRoot,
						Kind: arcset.KindMap, Backend: backend, ExpectedUses: 1,
						Changes: []mutation.IntentChange{{
							Coordinate: wasmMapCoordinate(t, "value"), Before: &beforeChildValue, After: &afterChildValue,
						}},
					},
				},
			}
			secondCandidate := prepareAndAcceptSessionIntent(t, session, "legacy-child-second", secondIntent)
			if got := session.session.BaseRoot(); !got.Equals(secondCandidate) {
				t.Fatalf("accepted base = %s, want %s", got, secondCandidate)
			}
		})
	}
}

func wasmMapCoordinate(t *testing.T, key string) arcset.CanonicalCoordinate {
	t.Helper()
	coordinate, err := arcset.NewMapCoordinate(key)
	if err != nil {
		t.Fatal(err)
	}
	return coordinate
}

func wasmObjectRootByID(t *testing.T, view mutation.UpdateView, objectID string) cid.Cid {
	t.Helper()
	for _, object := range view.Objects {
		if object.ObjectID == objectID {
			return object.Root
		}
	}
	t.Fatalf("update view has no object %q", objectID)
	return cid.Undef
}

func prepareAndAcceptSessionIntent(t *testing.T, session *sessionComputer, operationID string, intent mutation.SemanticIntent) cid.Cid {
	t.Helper()
	wireIntent, err := protocol.NewSemanticIntent(session.view, intent)
	if err != nil {
		t.Fatal(err)
	}
	intentJSON, err := json.Marshal(wireIntent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.prepare(t.Context(), operationID, intentJSON); err != nil {
		t.Fatalf("prepare %s: %v", operationID, err)
	}
	resultJSON, err := session.getPreparedResult(operationID)
	if err != nil {
		t.Fatal(err)
	}
	result, err := protocol.DecodeWriterComputeResult(resultJSON)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := result.Bundle.Core()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := bundle.Digest()
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := protocol.NewMaterializationReceipt(mutation.MaterializationReceipt{
		Profile: mutation.MaterializationReceiptProfile, OperationID: operationID,
		BaseRoot: bundle.View.BaseRoot, Candidate: bundle.Candidate,
		BundleDigest: digest, DurableBoundary: "unit-memory-v1",
	}, bundle)
	if err != nil {
		t.Fatal(err)
	}
	receiptJSON, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := session.acceptReceipt(operationID, receiptJSON)
	if err != nil {
		t.Fatalf("accept %s: %v", operationID, err)
	}
	if accepted != bundle.Candidate.String() {
		t.Fatalf("accepted root = %s, want %s", accepted, bundle.Candidate)
	}
	return bundle.Candidate
}

func TestSessionComputerDiscardReclaimsCandidateSnapshots(t *testing.T) {
	view, intent := computeFixture(t, maltcid.BackendKindIPA)
	wireView, err := protocol.NewUpdateView(view)
	if err != nil {
		t.Fatal(err)
	}
	wireIntent, err := protocol.NewSemanticIntent(view, intent)
	if err != nil {
		t.Fatal(err)
	}
	viewJSON, _ := json.Marshal(wireView)
	intentJSON, _ := json.Marshal(wireIntent)
	computer, err := newComputer("ipa")
	if err != nil {
		t.Fatal(err)
	}
	session, err := newSessionComputer(computer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.load(t.Context(), viewJSON); err != nil {
		t.Fatal(err)
	}
	baseline := session.store.EntryCount()
	if _, err := session.prepare(t.Context(), "discard-operation", intentJSON); err != nil {
		t.Fatal(err)
	}
	if got := session.store.EntryCount(); got <= baseline {
		t.Fatalf("prepare retained %d entries, want more than loaded baseline %d", got, baseline)
	}
	if err := session.discard("discard-operation"); err != nil {
		t.Fatal(err)
	}
	if got := session.store.EntryCount(); got != baseline {
		t.Fatalf("discard retained %d entries, want loaded baseline %d", got, baseline)
	}
	if _, err := session.getPreparedResult("discard-operation"); err == nil {
		t.Fatal("discarded operation remained available as a prepared result")
	}
}

func TestSessionComputerCloseReleasesStateAndAllowsReload(t *testing.T) {
	view, intent := computeFixture(t, maltcid.BackendKindKZG)
	wireView, err := protocol.NewUpdateView(view)
	if err != nil {
		t.Fatal(err)
	}
	wireIntent, err := protocol.NewSemanticIntent(view, intent)
	if err != nil {
		t.Fatal(err)
	}
	viewJSON, _ := json.Marshal(wireView)
	intentJSON, _ := json.Marshal(wireIntent)
	computer, err := newComputer("kzg")
	if err != nil {
		t.Fatal(err)
	}
	session, err := newSessionComputer(computer)
	if err != nil {
		t.Fatal(err)
	}

	session.closeSession()
	session.closeSession()
	if _, err := session.prepare(t.Context(), "before-load", intentJSON); err == nil {
		t.Fatal("closed session prepared without a loaded update view")
	}
	if _, err := session.load(t.Context(), viewJSON); err != nil {
		t.Fatal(err)
	}
	const operationID = "close-operation"
	if _, err := session.prepare(t.Context(), operationID, intentJSON); err != nil {
		t.Fatal(err)
	}
	firstStore := session.store
	firstSession := session.session
	if firstStore.EntryCount() == 0 {
		t.Fatal("loaded and prepared session retained no materialized state")
	}
	if _, err := session.load(t.Context(), []byte(`{}`)); err == nil {
		t.Fatal("session accepted an invalid replacement update view")
	}
	if session.store != firstStore || session.session != firstSession {
		t.Fatal("failed load replaced the current session")
	}
	if _, err := session.getPreparedResult(operationID); err != nil {
		t.Fatalf("failed load discarded the prepared result: %v", err)
	}

	if _, err := session.load(t.Context(), viewJSON); err != nil {
		t.Fatal(err)
	}
	if got := firstStore.EntryCount(); got != 0 {
		t.Fatalf("successful replacement retained %d entries in the old store", got)
	}
	if session.store == firstStore {
		t.Fatal("successful replacement reused the old store")
	}
	if _, err := session.getPreparedResult(operationID); err == nil {
		t.Fatal("successful replacement retained an old prepared result")
	}
	if _, err := session.prepare(t.Context(), operationID, intentJSON); err != nil {
		t.Fatalf("prepare after successful replacement failed: %v", err)
	}
	secondStore := session.store
	session.closeSession()
	session.closeSession()
	if got := secondStore.EntryCount(); got != 0 {
		t.Fatalf("closed session retained %d materialized entries", got)
	}
	if session.session != nil || session.store != nil || session.view.BaseRoot.Defined() || session.prepared != nil || session.preparedResponseBytes != 0 {
		t.Fatal("close did not clear all retained session state")
	}
	if _, err := session.getPreparedResult(operationID); err == nil {
		t.Fatal("closed session returned a prepared result")
	}
	if _, err := session.prepare(t.Context(), operationID, intentJSON); err == nil {
		t.Fatal("closed session prepared without reload")
	}
	if _, err := session.acceptReceipt(operationID, []byte(`{}`)); err == nil {
		t.Fatal("closed session accepted a receipt")
	}
	if err := session.discard(operationID); err == nil {
		t.Fatal("closed session discarded a candidate")
	}

	if _, err := session.load(t.Context(), viewJSON); err != nil {
		t.Fatalf("reload after close failed: %v", err)
	}
	if _, err := session.prepare(t.Context(), "after-close", intentJSON); err != nil {
		t.Fatalf("prepare after reload failed: %v", err)
	}
}

func computeFixture(t *testing.T, backend maltcid.BackendKind) (mutation.UpdateView, mutation.SemanticIntent) {
	t.Helper()
	ctx := context.Background()
	scheme := fixtureScheme(t, backend)
	semantic, err := mappingradix.NewMap(scheme, materializermemory.New(true))
	if err != nil {
		t.Fatalf("NewMap failed: %v", err)
	}
	before := payloadCID(t, "before")
	after := payloadCID(t, "after")
	root, err := semantic.Commit(ctx, "fixture", mapping.NewViewFrom(map[string]cid.Cid{"file": before}))
	if err != nil {
		t.Fatalf("Commit fixture failed: %v", err)
	}
	coordinate, err := arcset.NewMapCoordinate("file")
	if err != nil {
		t.Fatalf("NewMapCoordinate failed: %v", err)
	}
	entries, err := arcset.NewCanonicalArcSet(arcset.KindMap, []arcset.ArcEntry{{
		Coordinate: coordinate,
		Target:     arcset.NewCASTarget(before),
	}})
	if err != nil {
		t.Fatalf("NewCanonicalArcSet failed: %v", err)
	}
	view, err := mutation.NormalizeUpdateView(mutation.UpdateView{
		Profile: mutation.UpdateViewProfile, StateProfile: mutation.StatefulCompleteVectorsProfile,
		BaseRoot: root,
		Bounds:   mutation.UpdateViewBounds{MaxObjects: 8, MaxTotalEntries: 64, MaxDepth: 8},
		Objects: []mutation.UpdateObject{{
			ObjectID: "root", Root: root, Kind: arcset.KindMap, Entries: entries,
		}},
	})
	if err != nil {
		t.Fatalf("NormalizeUpdateView failed: %v", err)
	}
	beforeTarget := arcset.NewCASTarget(before)
	afterTarget := arcset.NewCASTarget(after)
	intent, err := mutation.NormalizeSemanticIntent(view, mutation.SemanticIntent{
		Profile: mutation.SemanticIntentProfile, BaseRoot: root, TopOutputID: "root-output",
		Transitions: []mutation.IntentTransition{{
			ID: "root-output", ObjectID: "root", OldRoot: root, Kind: arcset.KindMap,
			Backend: backend,
			Changes: []mutation.IntentChange{{
				Coordinate: coordinate, Before: &beforeTarget, After: &afterTarget,
			}},
		}},
	})
	if err != nil {
		t.Fatalf("NormalizeSemanticIntent failed: %v", err)
	}
	return view, intent
}

func fixtureScheme(t *testing.T, backend maltcid.BackendKind) commitment.IndexCommitment {
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
		t.Fatalf("unsupported fixture backend %q", backend)
	}
	if err != nil {
		t.Fatalf("NewScheme(%s) failed: %v", backend, err)
	}
	return scheme
}

func payloadCID(t *testing.T, value string) cid.Cid {
	t.Helper()
	digest, err := mh.Sum([]byte(value), mh.SHA2_256, -1)
	if err != nil {
		t.Fatalf("multihash: %v", err)
	}
	return cid.NewCidV1(cid.Raw, digest)
}

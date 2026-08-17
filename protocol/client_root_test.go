package protocol_test

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	"github.com/dewebprotocol/malt-core/mutation"
	"github.com/dewebprotocol/malt-core/protocol"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

func TestClientRootWireRoundTripsCoreValues(t *testing.T) {
	bundle, receipt := protocolClientRootFixture(t)
	wireBundle, err := protocol.NewClientRootBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(wireBundle)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := protocol.DecodeClientRootBundle(raw)
	if err != nil {
		t.Fatalf("DecodeClientRootBundle: %v", err)
	}
	if !reflect.DeepEqual(decoded, wireBundle) {
		t.Fatalf("decoded wire bundle differs\n got: %#v\nwant: %#v", decoded, wireBundle)
	}
	coreBundle, err := decoded.Core()
	if err != nil {
		t.Fatal(err)
	}
	wantDigest, err := bundle.Digest()
	if err != nil {
		t.Fatal(err)
	}
	gotDigest, err := coreBundle.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if gotDigest != wantDigest {
		t.Fatalf("bundle digest = %x, want %x", gotDigest, wantDigest)
	}

	wireView, err := protocol.NewUpdateView(bundle.View)
	if err != nil {
		t.Fatal(err)
	}
	viewRaw, err := json.Marshal(wireView)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := protocol.DecodeUpdateView(viewRaw); err != nil {
		t.Fatalf("DecodeUpdateView: %v", err)
	}
	wireIntent, err := protocol.NewSemanticIntent(bundle.View, bundle.Intent)
	if err != nil {
		t.Fatal(err)
	}
	intentRaw, err := json.Marshal(wireIntent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := protocol.DecodeSemanticIntent(intentRaw, bundle.View); err != nil {
		t.Fatalf("DecodeSemanticIntent: %v", err)
	}

	wireReceipt, err := protocol.NewMaterializationReceipt(receipt, bundle)
	if err != nil {
		t.Fatal(err)
	}
	receiptRaw, err := json.Marshal(wireReceipt)
	if err != nil {
		t.Fatal(err)
	}
	decodedReceipt, err := protocol.DecodeMaterializationReceipt(receiptRaw, bundle)
	if err != nil {
		t.Fatalf("DecodeMaterializationReceipt: %v", err)
	}
	coreReceipt, err := decodedReceipt.Core(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if coreReceipt.BundleDigest != receipt.BundleDigest || !coreReceipt.Candidate.Equals(receipt.Candidate) {
		t.Fatalf("receipt = %#v, want %#v", coreReceipt, receipt)
	}
}

func TestUpdateViewWireRoundTripsFullUint64ListCoordinate(t *testing.T) {
	root := protocolTypedRoot(t, arcset.KindList, 31)
	target := protocolTestCID(t, "uint64-list-target")
	entries, err := arcset.NewCanonicalArcSet(arcset.KindList, []arcset.ArcEntry{{
		Coordinate: arcset.NewListCoordinateUint64(math.MaxUint64),
		Target:     arcset.NewCASTarget(target),
	}})
	if err != nil {
		t.Fatal(err)
	}
	view := mutation.UpdateView{
		Profile:      mutation.UpdateViewProfile,
		StateProfile: mutation.StatefulCompleteVectorsProfile,
		BaseRoot:     root,
		Bounds:       mutation.UpdateViewBounds{MaxObjects: 1, MaxTotalEntries: 1, MaxDepth: 1},
		Objects: []mutation.UpdateObject{{
			ObjectID: "root", Root: root, Kind: arcset.KindList, Entries: entries,
		}},
	}
	wire, err := protocol.NewUpdateView(view)
	if err != nil {
		t.Fatal(err)
	}
	if got := wire.Objects[0].Entries[0].Coordinate.ListIndex; got != math.MaxUint64 {
		t.Fatalf("wire list index = %d, want %d", got, uint64(math.MaxUint64))
	}
	decoded, err := wire.Core()
	if err != nil {
		t.Fatal(err)
	}
	raw := decoded.Objects[0].Entries.Entries()[0].Coordinate.Bytes()
	if len(raw) != 8 || binary.BigEndian.Uint64(raw) != math.MaxUint64 {
		t.Fatalf("decoded coordinate = %x", raw)
	}
}

func TestClientRootDecodeRejectsUnknownDuplicateMissingNullTrailingAndOversized(t *testing.T) {
	bundle, _ := protocolClientRootFixture(t)
	wire, err := protocol.NewClientRootBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}

	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	object["unexpected"] = true
	assertBundleDecodeFails(t, object)

	duplicate := `{"profile":"` + protocol.ClientRootBundleProfile + `","profile":` + strings.TrimPrefix(string(raw), `{"profile":`)
	if _, err := protocol.DecodeClientRootBundle([]byte(duplicate)); err == nil || !strings.Contains(err.Error(), "duplicate field") {
		t.Fatalf("duplicate-field error = %v", err)
	}

	missing := cloneJSONMap(t, raw)
	view := missing["view"].(map[string]any)
	objects := view["objects"].([]any)
	commit := objects[0].(map[string]any)["commit"].(map[string]any)
	delete(commit, "total_size")
	assertBundleDecodeFails(t, missing)

	nullValue := cloneJSONMap(t, raw)
	nullValue["payload_cids"] = nil
	assertBundleDecodeFails(t, nullValue)

	if _, err := protocol.DecodeClientRootBundle(append(raw, []byte(`{}`)...)); err == nil {
		t.Fatal("DecodeClientRootBundle accepted trailing JSON")
	}
	oversized := make([]byte, protocol.MaxClientRootJSONBytes+1)
	if _, err := protocol.DecodeUpdateView(oversized); err == nil {
		t.Fatal("DecodeUpdateView accepted oversized JSON")
	}
}

func TestClientRootDecodeRejectsInvalidUTF8WithoutRejectingReplacementRune(t *testing.T) {
	bundle, _ := protocolClientRootFixture(t)
	wire, err := protocol.NewClientRootBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	childIndex := wireObjectIndex(t, &wire, "child")
	wire.View.Objects[childIndex].Entries[0].Coordinate.MapPath = "\uFFFD"
	validRaw, err := json.Marshal(wire.View)
	if err != nil {
		t.Fatal(err)
	}
	replacementRune := []byte("\uFFFD")
	if count := bytes.Count(validRaw, replacementRune); count != 1 {
		t.Fatalf("valid JSON contains %d replacement rune encodings, want 1: %q", count, validRaw)
	}
	if _, err := protocol.DecodeUpdateView(validRaw); err != nil {
		t.Fatalf("DecodeUpdateView rejected valid U+FFFD: %v", err)
	}

	invalidRaw := bytes.Replace(validRaw, replacementRune, []byte{0xff}, 1)
	if _, err := protocol.DecodeUpdateView(invalidRaw); err == nil || !strings.Contains(err.Error(), "not valid UTF-8") {
		t.Fatalf("invalid UTF-8 error = %v", err)
	}
}

func TestClientRootWireRejectsHostileDigestRootKindCoordinateDuplicateAndDependency(t *testing.T) {
	bundle, _ := protocolClientRootFixture(t)
	base, err := protocol.NewClientRootBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(*protocol.ClientRootBundle)
	}{
		{
			name: "wrong digest",
			mutate: func(value *protocol.ClientRootBundle) {
				value.ViewDigest = "0" + value.ViewDigest[1:]
				if value.ViewDigest == base.ViewDigest {
					value.ViewDigest = "1" + value.ViewDigest[1:]
				}
			},
		},
		{
			name: "wrong root",
			mutate: func(value *protocol.ClientRootBundle) {
				index := wireObjectIndex(t, value, "child")
				value.View.Objects[index].Root = protocolTypedRoot(t, arcset.KindList, 99).String()
			},
		},
		{
			name: "wrong target kind",
			mutate: func(value *protocol.ClientRootBundle) {
				index := wireObjectIndex(t, value, "parent")
				value.View.Objects[index].Entries[0].Target.Kind = arcset.TargetKindList
			},
		},
		{
			name: "noncanonical coordinate",
			mutate: func(value *protocol.ClientRootBundle) {
				index := wireObjectIndex(t, value, "child")
				value.View.Objects[index].Entries[0].Coordinate.MapPath = "payload//nested"
			},
		},
		{
			name: "duplicate coordinate",
			mutate: func(value *protocol.ClientRootBundle) {
				index := wireObjectIndex(t, value, "child")
				entry := value.View.Objects[index].Entries[0]
				value.View.Objects[index].Entries = append(value.View.Objects[index].Entries, entry)
			},
		},
		{
			name: "missing dependency",
			mutate: func(value *protocol.ClientRootBundle) {
				index := wireTransitionIndex(t, value, "top-output")
				value.Intent.Transitions[index].Changes[0].Output.ID = "missing-output"
			},
		},
		{
			name: "wrong output semantic kind",
			mutate: func(value *protocol.ClientRootBundle) {
				index := wireOutputIndex(t, value, "child-output")
				value.Outputs[index].Root = protocolTypedRoot(t, arcset.KindList, 88).String()
			},
		},
		{
			name: "wrong output backend",
			mutate: func(value *protocol.ClientRootBundle) {
				index := wireOutputIndex(t, value, "child-output")
				value.Outputs[index].Root = protocolIPARoot(t, arcset.KindMap, 77).String()
			},
		},
		{
			name: "missing literal payload",
			mutate: func(value *protocol.ClientRootBundle) {
				value.PayloadCIDs = []string{}
			},
		},
		{
			name: "extra literal payload",
			mutate: func(value *protocol.ClientRootBundle) {
				value.PayloadCIDs = append(value.PayloadCIDs, protocolTestCID(t, "extra-wire-payload").String())
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := cloneWireBundle(t, base)
			test.mutate(&value)
			if _, err := value.Core(); err == nil {
				t.Fatalf("Core accepted hostile %s", test.name)
			}
		})
	}
}

func TestMaterializationReceiptWireRejectsWrongDigest(t *testing.T) {
	bundle, receipt := protocolClientRootFixture(t)
	wire, err := protocol.NewMaterializationReceipt(receipt, bundle)
	if err != nil {
		t.Fatal(err)
	}
	wire.BundleDigest = strings.Repeat("0", 64)
	if wire.BundleDigest == strings.Repeat("0", 64) && receipt.BundleDigest == [32]byte{} {
		t.Fatal("fixture unexpectedly has zero bundle digest")
	}
	if _, err := wire.Core(bundle); err == nil {
		t.Fatal("receipt accepted wrong bundle digest")
	}
}

func TestWriterComputeResultRoundTripsAndBindsNextView(t *testing.T) {
	bundle, _ := protocolClientRootFixture(t)
	nextView, err := mutation.NormalizeUpdateView(bundle.View)
	if err != nil {
		t.Fatalf("NormalizeUpdateView failed: %v", err)
	}
	nextView.BaseRoot = bundle.Candidate
	for index := range nextView.Objects {
		if nextView.Objects[index].Root.Equals(bundle.View.BaseRoot) {
			nextView.Objects[index].Root = bundle.Candidate
		}
	}
	metrics := protocol.WriterComputeMetrics{CommitmentUpdateNS: 7, TotalNS: 11}
	entries, err := arcset.NewCanonicalArcSet(arcset.KindMap, []arcset.ArcEntry{{
		Coordinate: protocolMapCoordinate(t, "radix/node"),
		Target:     arcset.NewUnknownTarget(bundle.Candidate),
	}})
	if err != nil {
		t.Fatal(err)
	}
	materialization, err := mutation.NewClientRootMaterialization(bundle, mutation.ClientRootMaterialization{
		Profile: mutation.ClientRootMaterializationProfile,
		Maps: []mutation.MapMaterialization{{
			TransitionID: "child-output",
			Root:         bundle.Outputs[0].Root,
			Entries:      entries,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := protocol.NewWriterComputeResult(bundle, materialization, nextView, metrics)
	if err != nil {
		t.Fatalf("NewWriterComputeResult failed: %v", err)
	}
	data, err := json.Marshal(wire)
	if err != nil {
		t.Fatalf("marshal writer compute result: %v", err)
	}
	decoded, err := protocol.DecodeWriterComputeResult(data)
	if err != nil {
		t.Fatalf("DecodeWriterComputeResult failed: %v", err)
	}
	if decoded.Profile != protocol.WriterComputeResultProfile ||
		decoded.Bundle.Candidate != bundle.Candidate.String() ||
		decoded.NextView.BaseRoot != bundle.Candidate.String() ||
		decoded.Metrics != metrics {
		t.Fatalf("unexpected writer compute result: %+v", decoded)
	}

	longPath := wire
	longPath.Materialization.Maps = append([]protocol.MapMaterializationWire(nil), wire.Materialization.Maps...)
	longPath.Materialization.Maps[0].Entries = append([]protocol.MaterializationEntryWire(nil), wire.Materialization.Maps[0].Entries...)
	longPath.Materialization.Maps[0].Entries[0].Path = strings.Repeat("a", protocol.MaxClientRootPathBytes+1)
	if err := longPath.Validate(); err == nil {
		t.Fatal("writer compute result accepted an oversized materialization path")
	}

	noncanonicalPath := wire
	noncanonicalPath.Materialization.Maps = append([]protocol.MapMaterializationWire(nil), wire.Materialization.Maps...)
	noncanonicalPath.Materialization.Maps[0].Entries = append([]protocol.MaterializationEntryWire(nil), wire.Materialization.Maps[0].Entries...)
	noncanonicalPath.Materialization.Maps[0].Entries[0].Path = "radix//node"
	if err := noncanonicalPath.Validate(); err == nil || !strings.Contains(err.Error(), "path is not canonical") {
		t.Fatalf("noncanonical materialization path error = %v", err)
	}

	wire.NextView.BaseRoot = bundle.View.BaseRoot.String()
	if err := wire.Validate(); err == nil {
		t.Fatal("writer compute result accepted a next view at the wrong root")
	}
}

func TestWriterComputeResultV2RequiresMaterializationAndV1StillDecodes(t *testing.T) {
	bundle, _ := protocolClientRootFixture(t)
	nextView, err := mutation.NormalizeUpdateView(bundle.View)
	if err != nil {
		t.Fatal(err)
	}
	nextView.BaseRoot = bundle.Candidate
	for index := range nextView.Objects {
		if nextView.Objects[index].Root.Equals(bundle.View.BaseRoot) {
			nextView.Objects[index].Root = bundle.Candidate
		}
	}
	wireBundle, err := protocol.NewClientRootBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	wireView, err := protocol.NewUpdateView(nextView)
	if err != nil {
		t.Fatal(err)
	}
	legacyRaw, err := json.Marshal(map[string]any{
		"profile": protocol.WriterComputeResultProfileV1,
		"bundle":  wireBundle, "next_view": wireView, "metrics": protocol.WriterComputeMetrics{},
	})
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := protocol.DecodeWriterComputeResult(legacyRaw)
	if err != nil || legacy.Profile != protocol.WriterComputeResultProfileV1 {
		t.Fatalf("decode v1 result = %+v, %v", legacy, err)
	}
	roundTripRaw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	var roundTripObject map[string]json.RawMessage
	if err := json.Unmarshal(roundTripRaw, &roundTripObject); err != nil {
		t.Fatal(err)
	}
	if _, exists := roundTripObject["materialization"]; exists {
		t.Fatal("v1 writer result acquired a v2 materialization member")
	}
	if roundTrip, err := protocol.DecodeWriterComputeResult(roundTripRaw); err != nil || roundTrip.Profile != protocol.WriterComputeResultProfileV1 {
		t.Fatalf("round-trip v1 result = %+v, %v", roundTrip, err)
	}
	if _, err := protocol.DecodeWriterComputeResult([]byte(`{"profile":"malt.writer-compute-result/v2"}`)); err == nil {
		t.Fatal("v2 result without materialization was accepted")
	}
	legacyWithBase := legacy
	legacyWithBase.Materialization.Base = &protocol.MapStateMaterializationWire{Root: bundle.View.BaseRoot.String(), Entries: []protocol.MaterializationEntryWire{}}
	if err := legacyWithBase.Validate(); err == nil {
		t.Fatal("v1 writer result accepted a bootstrap base materialization")
	}
}

func TestWriterComputeResultRejectsExplicitNullBootstrapBase(t *testing.T) {
	raw := []byte(`{"profile":"malt.writer-compute-result/v2","materialization":{"profile":"malt.client-root-materialization/v1","base":null,"maps":[]},"bundle":{},"next_view":{},"metrics":{}}`)
	if _, err := protocol.DecodeWriterComputeResult(raw); err == nil || !strings.Contains(err.Error(), "materialization.base must not be null") {
		t.Fatalf("explicit null base error = %v", err)
	}
}

func TestWriterComputeResultRejectsOversizedMaterializationBeforeDecode(t *testing.T) {
	const item = `{"transition_id":"x","root":"x","entries":[]},`
	maps := strings.TrimSuffix(strings.Repeat(item, protocol.MaxClientRootTransitions+1), ",")
	raw := []byte(`{"profile":"malt.writer-compute-result/v2","materialization":{"profile":"malt.client-root-materialization/v1","maps":[` + maps + `]},"bundle":{},"next_view":{},"metrics":{}}`)
	if _, err := protocol.DecodeWriterComputeResult(raw); err == nil || !strings.Contains(err.Error(), "materialization.maps exceeds 65536 items") {
		t.Fatalf("oversized materialization maps error = %v", err)
	}
}

func TestClientRootSchemasAreEmbedded(t *testing.T) {
	want := map[string]bool{
		"update-view.schema.json":                 false,
		"semantic-intent.schema.json":             false,
		"client-root-bundle.schema.json":          false,
		"client-root-materialization.schema.json": false,
		"materialization-receipt.schema.json":     false,
		"writer-compute-result.schema.json":       false,
		"writer-compute-result-v2.schema.json":    false,
	}
	for _, name := range protocol.SchemaNames() {
		if _, ok := want[name]; ok {
			want[name] = true
			data, err := protocol.Schema(name)
			if err != nil {
				t.Fatal(err)
			}
			var schema map[string]any
			if err := json.Unmarshal(data, &schema); err != nil {
				t.Fatalf("schema %s: %v", name, err)
			}
			if schema["$id"] == nil {
				t.Fatalf("schema %s has no $id", name)
			}
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("SchemaNames does not include %s", name)
		}
	}
}

func protocolClientRootFixture(t *testing.T) (mutation.ClientRootBundle, mutation.MaterializationReceipt) {
	t.Helper()
	oldPayload := protocolTestCID(t, "protocol-old-payload")
	newPayload := protocolTestCID(t, "protocol-new-payload")
	childRoot := protocolTypedRoot(t, arcset.KindMap, 1)
	parentRoot := protocolTypedRoot(t, arcset.KindList, 2)
	childNewRoot := protocolTypedRoot(t, arcset.KindMap, 3)
	parentNewRoot := protocolTypedRoot(t, arcset.KindList, 4)

	childEntries, err := arcset.NewCanonicalArcSet(arcset.KindMap, []arcset.ArcEntry{{
		Coordinate: protocolMapCoordinate(t, "payload"),
		Target:     arcset.NewCASTarget(oldPayload),
	}})
	if err != nil {
		t.Fatal(err)
	}
	parentEntries, err := arcset.NewCanonicalArcSet(arcset.KindList, []arcset.ArcEntry{{
		Coordinate: arcset.NewListCoordinateUint64(0),
		Target:     arcset.NewMapTarget(childRoot),
	}})
	if err != nil {
		t.Fatal(err)
	}
	fixed := mutation.CommitDescriptor{FixedList: &mutation.FixedListCommit{TotalSize: 8, ChunkSize: 8}}
	view := mutation.UpdateView{
		Profile:      mutation.UpdateViewProfile,
		StateProfile: mutation.StatefulCompleteVectorsProfile,
		BaseRoot:     parentRoot,
		Bounds:       mutation.UpdateViewBounds{MaxObjects: 8, MaxTotalEntries: 64, MaxDepth: 8},
		Objects: []mutation.UpdateObject{
			{ObjectID: "parent", Root: parentRoot, Kind: arcset.KindList, Entries: parentEntries, Commit: fixed},
			{ObjectID: "child", Root: childRoot, Kind: arcset.KindMap, Entries: childEntries},
		},
	}
	oldPayloadTarget := arcset.NewCASTarget(oldPayload)
	newPayloadTarget := arcset.NewCASTarget(newPayload)
	childTarget := arcset.NewMapTarget(childRoot)
	intent := mutation.SemanticIntent{
		Profile: mutation.SemanticIntentProfile, BaseRoot: parentRoot, TopOutputID: "top-output",
		Transitions: []mutation.IntentTransition{
			{
				ID: "top-output", ObjectID: "parent", OldRoot: parentRoot, Kind: arcset.KindList,
				Backend: maltcid.BackendKindKZG, Commit: fixed,
				Changes: []mutation.IntentChange{{
					Coordinate: arcset.NewListCoordinateUint64(0), Before: &childTarget,
					OutputID: "child-output", OutputKind: arcset.TargetKindMap,
				}},
			},
			{
				ID: "child-output", ObjectID: "child", OldRoot: childRoot, Kind: arcset.KindMap,
				Backend: maltcid.BackendKindKZG, ExpectedUses: 1,
				Changes: []mutation.IntentChange{{
					Coordinate: protocolMapCoordinate(t, "payload"), Before: &oldPayloadTarget, After: &newPayloadTarget,
				}},
			},
		},
	}
	viewDigest, err := view.Digest()
	if err != nil {
		t.Fatal(err)
	}
	normalizedIntent, err := mutation.NormalizeSemanticIntent(view, intent)
	if err != nil {
		t.Fatal(err)
	}
	intentDigest, err := normalizedIntent.Digest()
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := mutation.NewClientRootBundle(mutation.ClientRootBundle{
		Profile: mutation.ClientRootBundleProfile, OperationID: "operation-1", View: view, Intent: intent,
		Outputs: []mutation.TransitionOutput{
			{TransitionID: "top-output", Root: parentNewRoot},
			{TransitionID: "child-output", Root: childNewRoot},
		},
		Candidate: parentNewRoot, PayloadCIDs: []cid.Cid{newPayload},
		ViewDigest: viewDigest, IntentDigest: intentDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	bundleDigest, err := bundle.Digest()
	if err != nil {
		t.Fatal(err)
	}
	receipt := mutation.MaterializationReceipt{
		Profile: mutation.MaterializationReceiptProfile, OperationID: bundle.OperationID,
		BaseRoot: bundle.View.BaseRoot, Candidate: bundle.Candidate, BundleDigest: bundleDigest,
		DurableBoundary: "embedded-transaction-commit-v1",
	}
	return bundle, receipt
}

func protocolTypedRoot(t *testing.T, kind arcset.Kind, seed byte) cid.Cid {
	t.Helper()
	commitment := make([]byte, maltcid.KZGCommitmentSize)
	for index := range commitment {
		commitment[index] = seed + byte(index)
	}
	var (
		root cid.Cid
		err  error
	)
	if kind == arcset.KindMap {
		root, err = maltcid.NewMapKZGCid(commitment)
	} else {
		root, err = maltcid.NewListKZGCid(commitment)
	}
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func protocolIPARoot(t *testing.T, kind arcset.Kind, seed byte) cid.Cid {
	t.Helper()
	commitment := make([]byte, maltcid.IPACommitmentSize)
	for index := range commitment {
		commitment[index] = seed + byte(index)
	}
	var (
		root cid.Cid
		err  error
	)
	if kind == arcset.KindMap {
		root, err = maltcid.NewMapIPACid(commitment)
	} else {
		root, err = maltcid.NewListIPACid(commitment)
	}
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func protocolMapCoordinate(t *testing.T, value string) arcset.CanonicalCoordinate {
	t.Helper()
	coordinate, err := arcset.NewMapCoordinate(value)
	if err != nil {
		t.Fatal(err)
	}
	return coordinate
}

func cloneWireBundle(t *testing.T, value protocol.ClientRootBundle) protocol.ClientRootBundle {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var cloned protocol.ClientRootBundle
	if err := json.Unmarshal(raw, &cloned); err != nil {
		t.Fatal(err)
	}
	return cloned
}

func wireObjectIndex(t *testing.T, value *protocol.ClientRootBundle, id string) int {
	t.Helper()
	for index, object := range value.View.Objects {
		if object.ObjectID == id {
			return index
		}
	}
	t.Fatalf("wire object %q not found", id)
	return -1
}

func wireTransitionIndex(t *testing.T, value *protocol.ClientRootBundle, id string) int {
	t.Helper()
	for index, transition := range value.Intent.Transitions {
		if transition.ID == id {
			return index
		}
	}
	t.Fatalf("wire transition %q not found", id)
	return -1
}

func wireOutputIndex(t *testing.T, value *protocol.ClientRootBundle, id string) int {
	t.Helper()
	for index, output := range value.Outputs {
		if output.TransitionID == id {
			return index
		}
	}
	t.Fatalf("wire output %q not found", id)
	return -1
}

func cloneJSONMap(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func assertBundleDecodeFails(t *testing.T, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := protocol.DecodeClientRootBundle(raw); err == nil {
		t.Fatalf("DecodeClientRootBundle accepted hostile JSON: %s", raw)
	}
}

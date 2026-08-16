package writer

import (
	"context"
	"errors"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	materializermemory "github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
	"github.com/dewebprotocol/malt-core/auth/commitment/kzg"
	listtree "github.com/dewebprotocol/malt-core/auth/semantic/list/tree"
	"github.com/dewebprotocol/malt-core/auth/semantic/mapping"
	mappingradix "github.com/dewebprotocol/malt-core/auth/semantic/mapping/radix"
	"github.com/dewebprotocol/malt-core/mutation"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

func TestComputeBundleMatchesIndependentFullRebuildAndRetainsNextView(t *testing.T) {
	ctx := context.Background()
	scheme, err := kzg.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	view, intent, expectedCandidate, newPayload := mapWriterFixture(t, ctx, scheme)
	runtime, err := NewRuntime(materializermemory.New(true), map[maltcid.BackendKind]commitment.IndexCommitment{
		maltcid.BackendKindKZG: scheme,
	})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := runtime.VerifyUpdateView(ctx, view)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runtime.ComputeBundle(ctx, "map-replace-1", verified, intent)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Bundle.Candidate.Equals(expectedCandidate) {
		t.Fatalf("candidate = %s, want independent full rebuild %s", result.Bundle.Candidate, expectedCandidate)
	}
	if len(result.Bundle.Outputs) != 2 || result.Bundle.Outputs[0].TransitionID != "child-output" || result.Bundle.Outputs[1].TransitionID != "top-output" {
		t.Fatalf("outputs = %#v", result.Bundle.Outputs)
	}
	if len(result.Bundle.PayloadCIDs) != 1 || !result.Bundle.PayloadCIDs[0].Equals(newPayload) {
		t.Fatalf("payload CIDs = %#v", result.Bundle.PayloadCIDs)
	}
	if !result.NextView.BaseRoot.Equals(result.Bundle.Candidate) {
		t.Fatalf("next view base = %s, candidate = %s", result.NextView.BaseRoot, result.Bundle.Candidate)
	}
	if result.Metrics.TotalNS < result.Metrics.RootComputationNS || result.Metrics.TotalNS == 0 ||
		result.Metrics.CommitmentUpdateNS == 0 || result.Metrics.CommitmentUpdateNS > result.Metrics.RootComputationNS ||
		result.Metrics.ExpectedRootEncodingNS == 0 {
		t.Fatalf("compute metrics = %#v", result.Metrics)
	}
	if result.Materialization.Profile != mutation.ClientRootMaterializationProfile || len(result.Materialization.Maps) != 2 {
		t.Fatalf("materialization = %#v", result.Materialization)
	}
	var mapWitness mutation.MapMaterialization
	for _, witness := range result.Materialization.Maps {
		if witness.TransitionID == "child-output" {
			mapWitness = witness
			break
		}
	}
	if mapWitness.TransitionID == "" || mapWitness.Entries == nil || mapWitness.Entries.Len() == 0 {
		t.Fatalf("map materialization = %#v", mapWitness)
	}
	var childEntries *arcset.CanonicalArcSet
	for _, object := range result.NextView.Objects {
		if object.ObjectID == "child" {
			childEntries = object.Entries
			break
		}
	}
	if childEntries == nil {
		t.Fatal("retained child object is missing")
	}
	logicalView, err := mapViewFromEntries(childEntries)
	if err != nil {
		t.Fatal(err)
	}
	if err := mappingradix.ValidateMaterialization(ctx, scheme, mapWitness.Root, logicalView, mapWitness.Entries); err != nil {
		t.Fatalf("validate exported map materialization without Commit: %v", err)
	}

	// A fresh runtime must independently accept the retained complete vectors;
	// this prevents a session-only materialization cache from hiding bad roots.
	fresh, err := NewRuntime(materializermemory.New(true), map[maltcid.BackendKind]commitment.IndexCommitment{
		maltcid.BackendKindKZG: scheme,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.VerifyUpdateView(ctx, result.NextView); err != nil {
		t.Fatalf("verify retained next view: %v", err)
	}
}

func TestBootstrapMapCreatesClientOwnedEmptyBase(t *testing.T) {
	ctx := context.Background()
	scheme, err := kzg.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := NewRuntime(materializermemory.New(true), map[maltcid.BackendKind]commitment.IndexCommitment{
		maltcid.BackendKindKZG: scheme,
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := NewSession(runtime)
	if err != nil {
		t.Fatal(err)
	}
	bounds := mutation.UpdateViewBounds{MaxObjects: 8, MaxTotalEntries: 64, MaxDepth: 8}
	view, base, err := session.BootstrapMap(ctx, maltcid.BackendKindKZG, bounds)
	if err != nil {
		t.Fatal(err)
	}
	if view.Bounds != bounds {
		t.Fatalf("bootstrap bounds = %+v, want %+v", view.Bounds, bounds)
	}
	if !session.BaseRoot().Equals(view.BaseRoot) || !base.Root.Equals(view.BaseRoot) {
		t.Fatalf("bootstrap roots = session %s, view %s, witness %s", session.BaseRoot(), view.BaseRoot, base.Root)
	}
	if len(view.Objects) != 1 || view.Objects[0].ObjectID != "root" || view.Objects[0].Kind != arcset.KindMap || view.Objects[0].Entries.Len() != 0 {
		t.Fatalf("bootstrap view = %+v", view)
	}
	if maltcid.BackendKindOf(view.BaseRoot) != maltcid.BackendKindKZG {
		t.Fatalf("bootstrap backend = %q", maltcid.BackendKindOf(view.BaseRoot))
	}
	if err := mappingradix.ValidateMaterialization(ctx, scheme, view.BaseRoot, mapping.NewViewFromPaths(nil), base.Entries); err != nil {
		t.Fatalf("ValidateMaterialization: %v", err)
	}
}

func TestNewRuntimeRequiresBranchingMaterializer(t *testing.T) {
	scheme, err := kzg.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewRuntime(materializermemory.New(false), map[maltcid.BackendKind]commitment.IndexCommitment{
		maltcid.BackendKindKZG: scheme,
	}); err == nil {
		t.Fatal("non-branching speculative client writer was accepted")
	}
}

func TestNextReachableViewRejectsDistinctObjectsConvergingToOneRoot(t *testing.T) {
	ctx := context.Background()
	scheme, err := kzg.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	view, _, _, _ := mapWriterFixture(t, ctx, scheme)
	objects := make(map[string]mutation.UpdateObject, len(view.Objects))
	for _, object := range view.Objects {
		objects[object.ObjectID] = object
	}
	child := objects["child"]
	child.Root = view.BaseRoot
	objects[child.ObjectID] = child

	if _, err := nextReachableView(view, view.BaseRoot, objects); err == nil {
		t.Fatal("distinct retained objects converging to one root were accepted")
	}
}

func TestFixedListReplaceAndAppendRetainVerifiableMetadataAcrossBackends(t *testing.T) {
	for _, backend := range []maltcid.BackendKind{maltcid.BackendKindKZG, maltcid.BackendKindIPA} {
		t.Run(string(backend), func(t *testing.T) {
			var (
				scheme commitment.IndexCommitment
				err    error
			)
			if backend == maltcid.BackendKindKZG {
				scheme, err = kzg.NewScheme()
			} else {
				scheme, err = ipa.NewScheme()
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, operation := range []string{"replace", "append"} {
				t.Run(operation, func(t *testing.T) {
					ctx := context.Background()
					oldValues := []cid.Cid{writerRawCID(t, "fixed-a"), writerRawCID(t, "fixed-b")}
					oldStore := materializermemory.New(true)
					semantic, err := listtree.NewList(scheme, oldStore)
					if err != nil {
						t.Fatal(err)
					}
					root, err := semantic.CommitFixed(ctx, "fixed-file", oldValues, 4, 8)
					if err != nil {
						t.Fatal(err)
					}
					entries, err := arcset.NewCanonicalArcSet(arcset.KindList, []arcset.ArcEntry{
						{Coordinate: arcset.NewListCoordinateUint64(0), Target: arcset.NewCASTarget(oldValues[0])},
						{Coordinate: arcset.NewListCoordinateUint64(1), Target: arcset.NewCASTarget(oldValues[1])},
					})
					if err != nil {
						t.Fatal(err)
					}
					view := mutation.UpdateView{
						Profile: mutation.UpdateViewProfile, StateProfile: mutation.StatefulCompleteVectorsProfile,
						BaseRoot: root, Bounds: mutation.UpdateViewBounds{MaxObjects: 2, MaxTotalEntries: 8, MaxDepth: 2},
						Objects: []mutation.UpdateObject{{ObjectID: "fixed-file", Root: root, Kind: arcset.KindList, Entries: entries,
							Commit: mutation.CommitDescriptor{FixedList: &mutation.FixedListCommit{ChunkSize: 4, TotalSize: 8}}}},
					}
					newValue := writerRawCID(t, "fixed-"+operation)
					intent := mutation.SemanticIntent{
						Profile: mutation.SemanticIntentProfile, BaseRoot: root, TopOutputID: "fixed-output",
						Transitions: []mutation.IntentTransition{{
							ID: "fixed-output", ObjectID: "fixed-file", OldRoot: root, Kind: arcset.KindList, Backend: backend,
							Commit: mutation.CommitDescriptor{FixedList: &mutation.FixedListCommit{ChunkSize: 4, TotalSize: 8}},
						}},
					}
					nextValues := append([]cid.Cid(nil), oldValues...)
					if operation == "replace" {
						before, after := arcset.NewCASTarget(oldValues[0]), arcset.NewCASTarget(newValue)
						intent.Transitions[0].Changes = []mutation.IntentChange{{Coordinate: arcset.NewListCoordinateUint64(0), Before: &before, After: &after}}
						nextValues[0] = newValue
					} else {
						after := arcset.NewCASTarget(newValue)
						intent.Transitions[0].Commit.FixedList.TotalSize = 12
						intent.Transitions[0].Changes = []mutation.IntentChange{{Coordinate: arcset.NewListCoordinateUint64(2), After: &after}}
						nextValues = append(nextValues, newValue)
					}

					runtime, err := NewRuntime(materializermemory.New(true), map[maltcid.BackendKind]commitment.IndexCommitment{backend: scheme})
					if err != nil {
						t.Fatal(err)
					}
					verified, err := runtime.VerifyUpdateView(ctx, view)
					if err != nil {
						t.Fatal(err)
					}
					result, err := runtime.ComputeBundle(ctx, "fixed-"+operation, verified, intent)
					if err != nil {
						t.Fatal(err)
					}
					expectedStore := materializermemory.New(true)
					expectedSemantic, err := listtree.NewList(scheme, expectedStore)
					if err != nil {
						t.Fatal(err)
					}
					expectedTotal := uint64(len(nextValues) * 4)
					expected, err := expectedSemantic.CommitFixed(ctx, "fixed-file", nextValues, 4, expectedTotal)
					if err != nil {
						t.Fatal(err)
					}
					if !result.Bundle.Candidate.Equals(expected) {
						t.Fatalf("candidate = %s, want %s", result.Bundle.Candidate, expected)
					}
					fresh, err := NewRuntime(materializermemory.New(true), map[maltcid.BackendKind]commitment.IndexCommitment{backend: scheme})
					if err != nil {
						t.Fatal(err)
					}
					if _, err := fresh.VerifyUpdateView(ctx, result.NextView); err != nil {
						t.Fatalf("verify retained fixed-list view: %v", err)
					}
				})
			}
		})
	}
}

func TestComputeBundleCreatesDependencyObjectWithoutWorkingRoot(t *testing.T) {
	ctx := context.Background()
	scheme, err := kzg.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	parentSemantic, err := mappingradix.NewMap(scheme, materializermemory.New(true))
	if err != nil {
		t.Fatal(err)
	}
	parentRoot, err := parentSemantic.Commit(ctx, "parent", mapping.NewViewFrom(map[string]cid.Cid{}))
	if err != nil {
		t.Fatal(err)
	}
	emptyEntries, err := arcset.NewCanonicalArcSet(arcset.KindMap, nil)
	if err != nil {
		t.Fatal(err)
	}
	payload := writerRawCID(t, "new-object-payload")
	view := mutation.UpdateView{
		Profile: mutation.UpdateViewProfile, StateProfile: mutation.StatefulCompleteVectorsProfile,
		BaseRoot: parentRoot, Bounds: mutation.UpdateViewBounds{MaxObjects: 4, MaxTotalEntries: 8, MaxDepth: 4},
		Objects: []mutation.UpdateObject{{ObjectID: "parent", Root: parentRoot, Kind: arcset.KindMap, Entries: emptyEntries}},
	}
	afterPayload := arcset.NewCASTarget(payload)
	intent := mutation.SemanticIntent{
		Profile: mutation.SemanticIntentProfile, BaseRoot: parentRoot, TopOutputID: "parent-output",
		Transitions: []mutation.IntentTransition{
			{
				ID: "parent-output", ObjectID: "parent", OldRoot: parentRoot, Kind: arcset.KindMap, Backend: maltcid.BackendKindKZG,
				Changes: []mutation.IntentChange{{
					Coordinate: writerMapCoordinate(t, "child"), OutputID: "child-output", OutputKind: arcset.TargetKindMap,
				}},
			},
			{
				ID: "child-output", ObjectID: "child", Kind: arcset.KindMap, Backend: maltcid.BackendKindKZG, ExpectedUses: 1,
				Changes: []mutation.IntentChange{{Coordinate: writerMapCoordinate(t, "payload"), After: &afterPayload}},
			},
		},
	}
	runtime, err := NewRuntime(materializermemory.New(true), map[maltcid.BackendKind]commitment.IndexCommitment{
		maltcid.BackendKindKZG: scheme,
	})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := runtime.VerifyUpdateView(ctx, view)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runtime.ComputeBundle(ctx, "create-child", verified, intent)
	if err != nil {
		t.Fatal(err)
	}
	childSemantic, err := mappingradix.NewMap(scheme, materializermemory.New(true))
	if err != nil {
		t.Fatal(err)
	}
	childRoot, err := childSemantic.Commit(ctx, "child", mapping.NewViewFrom(map[string]cid.Cid{"payload": payload}))
	if err != nil {
		t.Fatal(err)
	}
	expected, err := parentSemantic.Commit(ctx, "parent-expected", mapping.NewViewFrom(map[string]cid.Cid{"child": childRoot}))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Bundle.Candidate.Equals(expected) {
		t.Fatalf("candidate = %s, want %s", result.Bundle.Candidate, expected)
	}
}

func TestLegacyV2MapAndListViewsComputeCurrentCandidatesAcrossBackends(t *testing.T) {
	for _, backend := range []maltcid.BackendKind{maltcid.BackendKindKZG, maltcid.BackendKindIPA} {
		t.Run(string(backend), func(t *testing.T) {
			var (
				scheme commitment.IndexCommitment
				err    error
			)
			if backend == maltcid.BackendKindKZG {
				scheme, err = kzg.NewScheme()
			} else {
				scheme, err = ipa.NewScheme()
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, kind := range []arcset.Kind{arcset.KindMap, arcset.KindList} {
				t.Run(string(kind), func(t *testing.T) {
					ctx := context.Background()
					oldValue := writerRawCID(t, string(backend)+"-"+string(kind)+"-old")
					untouched := writerRawCID(t, string(backend)+"-"+string(kind)+"-untouched")
					newValue := writerRawCID(t, string(backend)+"-"+string(kind)+"-new")
					legacyStore := materializermemory.New(true)
					var (
						root     cid.Cid
						entries  *arcset.CanonicalArcSet
						change   mutation.IntentChange
						commit   mutation.CommitDescriptor
						expected cid.Cid
					)
					switch kind {
					case arcset.KindMap:
						legacy, err := mappingradix.NewMapForVersion(scheme, legacyStore, maltcid.LegacyMALTVersionID)
						if err != nil {
							t.Fatal(err)
						}
						root, err = legacy.Commit(ctx, "legacy-object", mapping.NewViewFrom(map[string]cid.Cid{
							"key": oldValue, "untouched": untouched,
						}))
						if err != nil {
							t.Fatal(err)
						}
						entries, err = arcset.NewCanonicalArcSet(kind, []arcset.ArcEntry{
							{Coordinate: writerMapCoordinate(t, "key"), Target: arcset.NewCASTarget(oldValue)},
							{Coordinate: writerMapCoordinate(t, "untouched"), Target: arcset.NewCASTarget(untouched)},
						})
						if err != nil {
							t.Fatal(err)
						}
						before, after := arcset.NewCASTarget(oldValue), arcset.NewCASTarget(newValue)
						change = mutation.IntentChange{Coordinate: writerMapCoordinate(t, "key"), Before: &before, After: &after}
						current, err := mappingradix.NewMap(scheme, materializermemory.New(true))
						if err != nil {
							t.Fatal(err)
						}
						expected, err = current.Commit(ctx, "legacy-object", mapping.NewViewFrom(map[string]cid.Cid{
							"key": newValue, "untouched": untouched,
						}))
						if err != nil {
							t.Fatal(err)
						}
					case arcset.KindList:
						legacy, err := listtree.NewListForVersion(scheme, legacyStore, maltcid.LegacyMALTVersionID)
						if err != nil {
							t.Fatal(err)
						}
						commit = mutation.CommitDescriptor{FixedList: &mutation.FixedListCommit{ChunkSize: 4, TotalSize: 8}}
						root, err = legacy.CommitFixed(ctx, "legacy-object", []cid.Cid{oldValue, untouched}, 4, 8)
						if err != nil {
							t.Fatal(err)
						}
						entries, err = arcset.NewCanonicalArcSet(kind, []arcset.ArcEntry{
							{Coordinate: arcset.NewListCoordinateUint64(0), Target: arcset.NewCASTarget(oldValue)},
							{Coordinate: arcset.NewListCoordinateUint64(1), Target: arcset.NewCASTarget(untouched)},
						})
						if err != nil {
							t.Fatal(err)
						}
						before, after := arcset.NewCASTarget(oldValue), arcset.NewCASTarget(newValue)
						change = mutation.IntentChange{Coordinate: arcset.NewListCoordinateUint64(0), Before: &before, After: &after}
						current, err := listtree.NewList(scheme, materializermemory.New(true))
						if err != nil {
							t.Fatal(err)
						}
						expected, err = current.CommitFixed(ctx, "legacy-object", []cid.Cid{newValue, untouched}, 4, 8)
						if err != nil {
							t.Fatal(err)
						}
					}
					if got := maltcid.VersionIDOf(root); got != maltcid.LegacyMALTVersionID {
						t.Fatalf("legacy root version = %d", got)
					}
					view := mutation.UpdateView{
						Profile: mutation.UpdateViewProfile, StateProfile: mutation.StatefulCompleteVectorsProfile,
						BaseRoot: root, Bounds: mutation.UpdateViewBounds{MaxObjects: 2, MaxTotalEntries: 8, MaxDepth: 2},
						Objects: []mutation.UpdateObject{{ObjectID: "legacy-object", Root: root, Kind: kind, Entries: entries, Commit: commit}},
					}
					intent := mutation.SemanticIntent{
						Profile: mutation.SemanticIntentProfile, BaseRoot: root, TopOutputID: "legacy-output",
						Transitions: []mutation.IntentTransition{{
							ID: "legacy-output", ObjectID: "legacy-object", OldRoot: root, Kind: kind, Backend: backend,
							Changes: []mutation.IntentChange{change}, Commit: commit,
						}},
					}
					runtime, err := NewRuntime(materializermemory.New(true), map[maltcid.BackendKind]commitment.IndexCommitment{backend: scheme})
					if err != nil {
						t.Fatal(err)
					}
					verified, err := runtime.VerifyUpdateView(ctx, view)
					if err != nil {
						t.Fatal(err)
					}
					result, err := runtime.ComputeBundle(ctx, "legacy-v2-"+string(kind), verified, intent)
					if err != nil {
						t.Fatal(err)
					}
					if !result.Bundle.Candidate.Equals(expected) {
						t.Fatalf("candidate = %s, want %s", result.Bundle.Candidate, expected)
					}
					if maltcid.VersionIDOf(result.Bundle.Candidate) != maltcid.MALTVersionID ||
						!result.Bundle.View.Objects[0].Root.Equals(root) {
						t.Fatal("bundle did not preserve v2 evidence while producing a current candidate")
					}
				})
			}
		})
	}
}

func TestVerifyUpdateViewRejectsUntrustedVectorForDeclaredRoot(t *testing.T) {
	ctx := context.Background()
	scheme, err := kzg.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	view, _, _, _ := mapWriterFixture(t, ctx, scheme)
	wrongPayload := arcset.NewCASTarget(writerRawCID(t, "tampered"))
	tamperedEntries, err := arcset.NewCanonicalArcSet(arcset.KindMap, []arcset.ArcEntry{{
		Coordinate: writerMapCoordinate(t, "payload"), Target: wrongPayload,
	}})
	if err != nil {
		t.Fatal(err)
	}
	for index := range view.Objects {
		if view.Objects[index].ObjectID == "child" {
			view.Objects[index].Entries = tamperedEntries
		}
	}
	runtime, err := NewRuntime(materializermemory.New(true), map[maltcid.BackendKind]commitment.IndexCommitment{
		maltcid.BackendKindKZG: scheme,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.VerifyUpdateView(ctx, view); err == nil {
		t.Fatal("tampered complete vector was accepted")
	}
}

func TestComputeBundleRejectsMutationOfVerifiedUpdateView(t *testing.T) {
	ctx := context.Background()
	scheme, err := kzg.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	view, intent, _, _ := mapWriterFixture(t, ctx, scheme)
	runtime, err := NewRuntime(materializermemory.New(true), map[maltcid.BackendKind]commitment.IndexCommitment{
		maltcid.BackendKindKZG: scheme,
	})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := runtime.VerifyUpdateView(ctx, view)
	if err != nil {
		t.Fatal(err)
	}
	for index := range verified.View.Objects {
		if verified.View.Objects[index].ObjectID != "child" {
			continue
		}
		entries := verified.View.Objects[index].Entries.Entries()
		for entryIndex := range entries {
			if entries[entryIndex].Coordinate.String() == "untouched" {
				entries[entryIndex].Target = arcset.NewCASTarget(writerRawCID(t, "forged-unmeasured-binding"))
			}
		}
		tampered, err := arcset.NewCanonicalArcSet(arcset.KindMap, entries)
		if err != nil {
			t.Fatal(err)
		}
		verified.View.Objects[index].Entries = tampered
	}
	if _, err := runtime.ComputeBundle(ctx, "mutated-verified-view", verified, intent); err == nil {
		t.Fatal("mutation of a verified update view bypassed its runtime seal")
	}
}

func TestComputeBundleRejectsDependencyTamperingBeforeComputation(t *testing.T) {
	ctx := context.Background()
	scheme, err := kzg.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	view, intent, _, _ := mapWriterFixture(t, ctx, scheme)
	for index := range intent.Transitions {
		if intent.Transitions[index].ID == "child-output" {
			intent.Transitions[index].ExpectedUses = 2
		}
	}
	runtime, err := NewRuntime(materializermemory.New(true), map[maltcid.BackendKind]commitment.IndexCommitment{
		maltcid.BackendKindKZG: scheme,
	})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := runtime.VerifyUpdateView(ctx, view)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.ComputeBundle(ctx, "tampered-dependency", verified, intent); !errors.Is(err, mutation.ErrIntentMultiplicity) {
		t.Fatalf("error = %v, want ErrIntentMultiplicity", err)
	}
}

func TestSessionAdvancesOnlyAfterExactDurableReceipt(t *testing.T) {
	ctx := context.Background()
	scheme, err := kzg.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	view, intent, _, _ := mapWriterFixture(t, ctx, scheme)
	runtime, err := NewRuntime(materializermemory.New(true), map[maltcid.BackendKind]commitment.IndexCommitment{
		maltcid.BackendKindKZG: scheme,
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := NewSession(runtime)
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Load(ctx, view); err != nil {
		t.Fatal(err)
	}
	prepared, err := session.Prepare(ctx, "session-map-replace", intent)
	if err != nil {
		t.Fatal(err)
	}
	if !session.BaseRoot().Equals(view.BaseRoot) {
		t.Fatal("preparing a candidate advanced the accepted session base")
	}
	digest, err := prepared.Bundle.Digest()
	if err != nil {
		t.Fatal(err)
	}
	wrong := mutation.MaterializationReceipt{
		Profile: mutation.MaterializationReceiptProfile, OperationID: prepared.Bundle.OperationID,
		BaseRoot: prepared.Bundle.View.BaseRoot, Candidate: view.BaseRoot,
		BundleDigest: digest, DurableBoundary: "embedded-transaction-commit-v1",
	}
	if err := session.AcceptReceipt(wrong, prepared); err == nil {
		t.Fatal("session accepted a substituted receipt candidate")
	}
	if !session.BaseRoot().Equals(view.BaseRoot) {
		t.Fatal("rejected receipt advanced the accepted session base")
	}
	reprepared, err := session.Prepare(ctx, "session-map-replace-retry", intent)
	if err != nil {
		t.Fatalf("prepare after rejected receipt: %v", err)
	}
	if !reprepared.Bundle.Candidate.Equals(prepared.Bundle.Candidate) {
		t.Fatalf("retry candidate = %s, want %s", reprepared.Bundle.Candidate, prepared.Bundle.Candidate)
	}
	correct := wrong
	correct.Candidate = prepared.Bundle.Candidate
	if err := session.AcceptReceipt(correct, prepared); err != nil {
		t.Fatal(err)
	}
	if !session.BaseRoot().Equals(prepared.Bundle.Candidate) {
		t.Fatalf("session base = %s, want %s", session.BaseRoot(), prepared.Bundle.Candidate)
	}
	if err := session.Audit(ctx); err != nil {
		t.Fatalf("final session audit: %v", err)
	}
}

func TestSessionRejectsMutationOfPreparedNextView(t *testing.T) {
	ctx := context.Background()
	scheme, err := kzg.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	view, intent, _, _ := mapWriterFixture(t, ctx, scheme)
	runtime, err := NewRuntime(materializermemory.New(true), map[maltcid.BackendKind]commitment.IndexCommitment{
		maltcid.BackendKindKZG: scheme,
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := NewSession(runtime)
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Load(ctx, view); err != nil {
		t.Fatal(err)
	}
	prepared, err := session.Prepare(ctx, "session-seal", intent)
	if err != nil {
		t.Fatal(err)
	}
	bundleDigest, err := prepared.Bundle.Digest()
	if err != nil {
		t.Fatal(err)
	}
	receipt := mutation.MaterializationReceipt{
		Profile: mutation.MaterializationReceiptProfile, OperationID: prepared.Bundle.OperationID,
		BaseRoot: prepared.Bundle.View.BaseRoot, Candidate: prepared.Bundle.Candidate,
		BundleDigest: bundleDigest, DurableBoundary: "embedded-transaction-commit-v1",
	}
	for index := range prepared.NextView.Objects {
		if prepared.NextView.Objects[index].ObjectID == "child" {
			prepared.NextView.Objects[index].Root = writerRawCID(t, "forged-next-root")
		}
	}
	if err := session.AcceptReceipt(receipt, prepared); err == nil {
		t.Fatal("session accepted a mutated prepared next view")
	}
	if !session.BaseRoot().Equals(view.BaseRoot) {
		t.Fatal("rejected prepared result advanced the session")
	}
}

func TestSessionRejectsPreparedResultAfterSameRootViewReload(t *testing.T) {
	ctx := context.Background()
	scheme, err := kzg.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	view, intent, _, _ := mapWriterFixture(t, ctx, scheme)
	runtime, err := NewRuntime(materializermemory.New(true), map[maltcid.BackendKind]commitment.IndexCommitment{
		maltcid.BackendKindKZG: scheme,
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := NewSession(runtime)
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Load(ctx, view); err != nil {
		t.Fatal(err)
	}
	prepared, err := session.Prepare(ctx, "session-stale-view", intent)
	if err != nil {
		t.Fatal(err)
	}
	bundleDigest, err := prepared.Bundle.Digest()
	if err != nil {
		t.Fatal(err)
	}
	receipt := mutation.MaterializationReceipt{
		Profile: mutation.MaterializationReceiptProfile, OperationID: prepared.Bundle.OperationID,
		BaseRoot: prepared.Bundle.View.BaseRoot, Candidate: prepared.Bundle.Candidate,
		BundleDigest: bundleDigest, DurableBoundary: "embedded-transaction-commit-v1",
	}

	reloaded := view
	reloaded.Bounds.MaxObjects++
	if err := session.Load(ctx, reloaded); err != nil {
		t.Fatal(err)
	}
	if err := session.AcceptReceipt(receipt, prepared); err == nil {
		t.Fatal("session accepted a result prepared against a different same-root view")
	}
	if !session.BaseRoot().Equals(view.BaseRoot) {
		t.Fatal("rejected stale prepared result advanced the session")
	}
}

func mapWriterFixture(t *testing.T, ctx context.Context, scheme *kzg.Scheme) (mutation.UpdateView, mutation.SemanticIntent, cid.Cid, cid.Cid) {
	t.Helper()
	oldPayload := writerRawCID(t, "old-payload")
	newPayload := writerRawCID(t, "new-payload")
	oldStore := materializermemory.New(true)
	oldMap, err := mappingradix.NewMap(scheme, oldStore)
	if err != nil {
		t.Fatal(err)
	}
	untouchedPayload := writerRawCID(t, "untouched-payload")
	childRoot, err := oldMap.Commit(ctx, "child", mapping.NewViewFrom(map[string]cid.Cid{"payload": oldPayload, "untouched": untouchedPayload}))
	if err != nil {
		t.Fatal(err)
	}
	parentRoot, err := oldMap.Commit(ctx, "parent", mapping.NewViewFrom(map[string]cid.Cid{"child": childRoot}))
	if err != nil {
		t.Fatal(err)
	}

	newStore := materializermemory.New(true)
	newMap, err := mappingradix.NewMap(scheme, newStore)
	if err != nil {
		t.Fatal(err)
	}
	newChildRoot, err := newMap.Commit(ctx, "child", mapping.NewViewFrom(map[string]cid.Cid{"payload": newPayload, "untouched": untouchedPayload}))
	if err != nil {
		t.Fatal(err)
	}
	expectedCandidate, err := newMap.Commit(ctx, "parent", mapping.NewViewFrom(map[string]cid.Cid{"child": newChildRoot}))
	if err != nil {
		t.Fatal(err)
	}

	childEntries, err := arcset.NewCanonicalArcSet(arcset.KindMap, []arcset.ArcEntry{
		{Coordinate: writerMapCoordinate(t, "payload"), Target: arcset.NewCASTarget(oldPayload)},
		{Coordinate: writerMapCoordinate(t, "untouched"), Target: arcset.NewCASTarget(untouchedPayload)},
	})
	if err != nil {
		t.Fatal(err)
	}
	parentEntries, err := arcset.NewCanonicalArcSet(arcset.KindMap, []arcset.ArcEntry{{
		Coordinate: writerMapCoordinate(t, "child"), Target: arcset.NewMapTarget(childRoot),
	}})
	if err != nil {
		t.Fatal(err)
	}
	view := mutation.UpdateView{
		Profile: mutation.UpdateViewProfile, StateProfile: mutation.StatefulCompleteVectorsProfile,
		BaseRoot: parentRoot, Bounds: mutation.UpdateViewBounds{MaxObjects: 8, MaxTotalEntries: 64, MaxDepth: 8},
		Objects: []mutation.UpdateObject{
			{ObjectID: "parent", Root: parentRoot, Kind: arcset.KindMap, Entries: parentEntries},
			{ObjectID: "child", Root: childRoot, Kind: arcset.KindMap, Entries: childEntries},
		},
	}
	oldPayloadTarget := arcset.NewCASTarget(oldPayload)
	newPayloadTarget := arcset.NewCASTarget(newPayload)
	oldChildTarget := arcset.NewMapTarget(childRoot)
	intent := mutation.SemanticIntent{
		Profile: mutation.SemanticIntentProfile, BaseRoot: parentRoot, TopOutputID: "top-output",
		Transitions: []mutation.IntentTransition{
			{
				ID: "top-output", ObjectID: "parent", OldRoot: parentRoot, Kind: arcset.KindMap, Backend: maltcid.BackendKindKZG,
				Changes: []mutation.IntentChange{{
					Coordinate: writerMapCoordinate(t, "child"), Before: &oldChildTarget,
					OutputID: "child-output", OutputKind: arcset.TargetKindMap,
				}},
			},
			{
				ID: "child-output", ObjectID: "child", OldRoot: childRoot, Kind: arcset.KindMap, Backend: maltcid.BackendKindKZG,
				ExpectedUses: 1,
				Changes: []mutation.IntentChange{{
					Coordinate: writerMapCoordinate(t, "payload"), Before: &oldPayloadTarget, After: &newPayloadTarget,
				}},
			},
		},
	}
	return view, intent, expectedCandidate, newPayload
}

func writerMapCoordinate(t *testing.T, value string) arcset.CanonicalCoordinate {
	t.Helper()
	coordinate, err := arcset.NewMapCoordinate(value)
	if err != nil {
		t.Fatal(err)
	}
	return coordinate
}

func writerRawCID(t *testing.T, value string) cid.Cid {
	t.Helper()
	hash, err := mh.Sum([]byte(value), mh.SHA2_256, -1)
	if err != nil {
		t.Fatal(err)
	}
	return cid.NewCidV1(cid.Raw, hash)
}

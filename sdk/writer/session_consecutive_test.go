package writer

import (
	"context"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	materializermemory "github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
	"github.com/dewebprotocol/malt-core/auth/commitment/kzg"
	"github.com/dewebprotocol/malt-core/mutation"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

func TestBootstrapSessionSupportsNestedFirstWriteAndConsecutiveReceipts(t *testing.T) {
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
			runtime, err := NewRuntime(materializermemory.New(true), map[maltcid.BackendKind]commitment.IndexCommitment{backend: scheme})
			if err != nil {
				t.Fatal(err)
			}
			session, err := NewSession(runtime)
			if err != nil {
				t.Fatal(err)
			}
			bounds := mutation.UpdateViewBounds{MaxObjects: 8, MaxTotalEntries: 32, MaxDepth: 4}
			view, _, err := session.BootstrapMap(context.Background(), backend, bounds)
			if err != nil {
				t.Fatal(err)
			}

			childOne := arcset.NewCASTarget(writerRawCID(t, string(backend)+"-child-one"))
			childTwo := arcset.NewCASTarget(writerRawCID(t, string(backend)+"-child-two"))
			metadata := arcset.NewCASTarget(writerRawCID(t, string(backend)+"-metadata"))
			firstIntent := mutation.SemanticIntent{
				Profile:     mutation.SemanticIntentProfile,
				BaseRoot:    view.BaseRoot,
				TopOutputID: "root-output-1",
				Transitions: []mutation.IntentTransition{
					{
						ID: "root-output-1", ObjectID: "root", OldRoot: view.BaseRoot,
						Kind: arcset.KindMap, Backend: backend,
						Changes: []mutation.IntentChange{
							{Coordinate: writerMapCoordinate(t, "child"), OutputID: "child-output-1", OutputKind: arcset.TargetKindMap},
							{Coordinate: writerMapCoordinate(t, "metadata"), After: &metadata},
						},
					},
					{
						ID: "child-output-1", ObjectID: "child", Kind: arcset.KindMap, Backend: backend, ExpectedUses: 1,
						Changes: []mutation.IntentChange{
							{Coordinate: writerMapCoordinate(t, "one"), After: &childOne},
							{Coordinate: writerMapCoordinate(t, "two"), After: &childTwo},
						},
					},
				},
			}
			first, err := session.Prepare(context.Background(), "bootstrap-nested-first", firstIntent)
			if err != nil {
				t.Fatalf("first prepare: %v", err)
			}
			if first.NextView.Bounds != bounds || len(first.NextView.Objects) != 2 {
				t.Fatalf("first next view bounds/objects = %+v/%d", first.NextView.Bounds, len(first.NextView.Objects))
			}
			acceptTestWriterResult(t, session, first)

			childRoot := objectRootByID(t, first.NextView, "child")
			beforeChild := arcset.NewMapTarget(childRoot)
			childThree := arcset.NewCASTarget(writerRawCID(t, string(backend)+"-child-three"))
			secondIntent := mutation.SemanticIntent{
				Profile:     mutation.SemanticIntentProfile,
				BaseRoot:    first.Bundle.Candidate,
				TopOutputID: "root-output-2",
				Transitions: []mutation.IntentTransition{
					{
						ID: "root-output-2", ObjectID: "root", OldRoot: first.Bundle.Candidate,
						Kind: arcset.KindMap, Backend: backend,
						Changes: []mutation.IntentChange{{
							Coordinate: writerMapCoordinate(t, "child"), Before: &beforeChild,
							OutputID: "child-output-2", OutputKind: arcset.TargetKindMap,
						}},
					},
					{
						ID: "child-output-2", ObjectID: "child", OldRoot: childRoot,
						Kind: arcset.KindMap, Backend: backend, ExpectedUses: 1,
						Changes: []mutation.IntentChange{{Coordinate: writerMapCoordinate(t, "three"), After: &childThree}},
					},
				},
			}
			second, err := session.Prepare(context.Background(), "bootstrap-nested-second", secondIntent)
			if err != nil {
				t.Fatalf("second prepare after accepted receipt: %v", err)
			}
			acceptTestWriterResult(t, session, second)
			if !session.BaseRoot().Equals(second.Bundle.Candidate) {
				t.Fatalf("accepted base = %s, want %s", session.BaseRoot(), second.Bundle.Candidate)
			}
		})
	}
}

func acceptTestWriterResult(t *testing.T, session *Session, result ComputeResult) {
	t.Helper()
	digest, err := result.Bundle.Digest()
	if err != nil {
		t.Fatal(err)
	}
	receipt := mutation.MaterializationReceipt{
		Profile:         mutation.MaterializationReceiptProfile,
		OperationID:     result.Bundle.OperationID,
		BaseRoot:        result.Bundle.View.BaseRoot,
		Candidate:       result.Bundle.Candidate,
		BundleDigest:    digest,
		DurableBoundary: "unit-memory-v1",
	}
	if err := session.AcceptReceipt(receipt, result); err != nil {
		t.Fatalf("accept receipt: %v", err)
	}
}

func objectRootByID(t *testing.T, view mutation.UpdateView, objectID string) cid.Cid {
	t.Helper()
	for _, object := range view.Objects {
		if object.ObjectID == objectID {
			return object.Root
		}
	}
	t.Fatalf("update view has no object %q", objectID)
	return cid.Undef
}

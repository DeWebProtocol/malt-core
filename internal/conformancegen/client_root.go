package conformancegen

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	materialmemory "github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
	"github.com/dewebprotocol/malt-core/auth/commitment/kzg"
	"github.com/dewebprotocol/malt-core/auth/semantic/mapping"
	mapradix "github.com/dewebprotocol/malt-core/auth/semantic/mapping/radix"
	"github.com/dewebprotocol/malt-core/conformance"
	"github.com/dewebprotocol/malt-core/mutation"
	"github.com/dewebprotocol/malt-core/protocol"
	clientwriter "github.com/dewebprotocol/malt-core/sdk/writer"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

// GenerateClientRoot reproduces the frozen v1 corpus with historical V3 output.
func GenerateClientRoot() ([]byte, error) {
	return generateClientRoot(conformance.ClientRootV1)
}

// GenerateClientRootV2 freezes V0 candidate output for both V0 and historical V3
// input views. The corpus revision is independent of the Root format version.
func GenerateClientRootV2() ([]byte, error) {
	return generateClientRoot(conformance.ClientRootV2)
}

func generateClientRoot(version string) ([]byte, error) {
	baseVersions := []uint8{maltcid.MALTVersionID}
	targetVersion := maltcid.MALTVersionID
	if version == conformance.ClientRootV2 {
		baseVersions = []uint8{maltcid.RootVersion, maltcid.MALTVersionID}
		targetVersion = maltcid.RootVersion
	}
	var vectors []conformance.ClientRootVector
	for _, backend := range []maltcid.BackendKind{maltcid.BackendKindKZG, maltcid.BackendKindIPA} {
		for _, baseVersion := range baseVersions {
			generated, err := generateClientRootBackend(backend, baseVersion, targetVersion)
			if err != nil {
				return nil, err
			}
			vectors = append(vectors, generated...)
		}
	}

	slices.SortFunc(vectors, func(left, right conformance.ClientRootVector) int {
		if left.ID < right.ID {
			return -1
		}
		if left.ID > right.ID {
			return 1
		}
		return 0
	})
	corpus := conformance.ClientRootCorpus{SchemaVersion: version, Vectors: vectors}
	if err := corpus.Validate(); err != nil {
		return nil, fmt.Errorf("validate generated client-root corpus: %w", err)
	}
	data, err := json.MarshalIndent(corpus, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal generated client-root corpus: %w", err)
	}
	return append(data, '\n'), nil
}

func generateClientRootBackend(backend maltcid.BackendKind, baseVersion, targetVersion uint8) ([]conformance.ClientRootVector, error) {
	ctx := context.Background()
	scheme, err := clientRootScheme(backend)
	if err != nil {
		return nil, err
	}
	view, intent, err := clientRootInput(ctx, backend, scheme, baseVersion)
	if err != nil {
		return nil, err
	}
	wireView, err := protocol.NewUpdateView(view)
	if err != nil {
		return nil, err
	}
	wireIntent, err := protocol.NewSemanticIntent(view, intent)
	if err != nil {
		return nil, err
	}
	viewJSON, err := json.Marshal(wireView)
	if err != nil {
		return nil, err
	}
	intentJSON, err := json.Marshal(wireIntent)
	if err != nil {
		return nil, err
	}
	operationID := "client-root-" + string(backend) + "-replace"
	prefix := "client-root." + string(backend) + "."
	category := "replace"
	newRuntime := clientwriter.NewHistoricalRuntime
	if targetVersion == maltcid.RootVersion {
		newRuntime = clientwriter.NewRuntime
		prefix = fmt.Sprintf("client-root-v%d-to-v0.%s.", baseVersion, backend)
		operationID = fmt.Sprintf("client-root-v%d-to-v0-%s-replace", baseVersion, backend)
		if baseVersion == maltcid.MALTVersionID {
			category = "migrate_v3"
		}
	}
	runtime, err := newRuntime(
		materialmemory.New(true),
		map[maltcid.BackendKind]commitment.IndexCommitment{backend: scheme},
	)
	if err != nil {
		return nil, err
	}
	verified, err := runtime.VerifyUpdateView(ctx, view)
	if err != nil {
		return nil, err
	}
	result, err := runtime.ComputeBundle(ctx, operationID, verified, intent)
	if err != nil {
		return nil, err
	}
	wireBundle, err := protocol.NewClientRootBundle(result.Bundle)
	if err != nil {
		return nil, err
	}
	wireMaterialization, err := protocol.NewClientRootMaterialization(result.Bundle, result.Materialization)
	if err != nil {
		return nil, err
	}
	wireNextView, err := protocol.NewUpdateView(result.NextView)
	if err != nil {
		return nil, err
	}
	bundleDigest, err := result.Bundle.Digest()
	if err != nil {
		return nil, err
	}
	wireReceipt, err := protocol.NewMaterializationReceipt(mutation.MaterializationReceipt{
		Profile: mutation.MaterializationReceiptProfile, OperationID: operationID,
		BaseRoot: result.Bundle.View.BaseRoot, Candidate: result.Bundle.Candidate,
		BundleDigest: bundleDigest, DurableBoundary: "conformance-memory-v1",
	}, result.Bundle)
	if err != nil {
		return nil, err
	}
	vectors := []conformance.ClientRootVector{{
		ID: prefix + "replace.accept", Backend: string(backend), Category: category, OperationID: operationID,
		UpdateView: viewJSON, SemanticIntent: intentJSON,
		Expected: conformance.ClientRootExpected{
			Valid: true, Bundle: &wireBundle, Materialization: &wireMaterialization,
			NextView: &wireNextView, Receipt: &wireReceipt,
		},
	}}
	appendInvalid := func(id, category string, inputView, inputIntent json.RawMessage) {
		vectors = append(vectors, conformance.ClientRootVector{
			ID: id, Backend: string(backend), Category: category,
			OperationID: id, UpdateView: inputView, SemanticIntent: inputIntent,
			Expected: conformance.ClientRootExpected{Valid: false},
		})
	}

	staleIntent, err := mutateJSONObject(intentJSON, func(value map[string]any) error {
		other, err := rawCID("client-root-stale-" + string(backend))
		if err != nil {
			return err
		}
		value["base_root"] = other.String()
		return nil
	})
	if err != nil {
		return nil, err
	}
	appendInvalid(prefix+"stale-base.reject", "stale_base", viewJSON, staleIntent)

	tamperedTarget, err := rawCID("client-root-view-tamper-" + string(backend))
	if err != nil {
		return nil, err
	}
	tamperSemantic, err := mapradix.NewMapForVersion(scheme, materialmemory.New(true), baseVersion)
	if err != nil {
		return nil, err
	}
	tamperedRoot, err := tamperSemantic.Commit(
		ctx,
		"client-root-conformance-v1-tamper",
		mapping.NewViewFrom(map[string]cid.Cid{"file": tamperedTarget}),
	)
	if err != nil {
		return nil, err
	}
	if tamperedRoot.Equals(view.BaseRoot) {
		return nil, fmt.Errorf("generated client-root tamper root matches the original root")
	}
	tamperedView, err := mutateJSONObject(viewJSON, func(value map[string]any) error {
		objects, ok := value["objects"].([]any)
		if !ok || len(objects) == 0 {
			return fmt.Errorf("generated client-root view has no objects")
		}
		object, ok := objects[0].(map[string]any)
		if !ok {
			return fmt.Errorf("generated client-root object is invalid")
		}
		value["base_root"] = tamperedRoot.String()
		object["root"] = tamperedRoot.String()
		return nil
	})
	if err != nil {
		return nil, err
	}
	tamperedIntent, err := mutateJSONObject(intentJSON, func(value map[string]any) error {
		transitions, ok := value["transitions"].([]any)
		if !ok || len(transitions) == 0 {
			return fmt.Errorf("generated client-root intent has no transitions")
		}
		transition, ok := transitions[0].(map[string]any)
		if !ok {
			return fmt.Errorf("generated client-root transition is invalid")
		}
		value["base_root"] = tamperedRoot.String()
		transition["old_root"] = map[string]any{"state": "present", "cid": tamperedRoot.String()}
		return nil
	})
	if err != nil {
		return nil, err
	}
	appendInvalid(prefix+"view-root-tamper.reject", "view_tamper", tamperedView, tamperedIntent)

	wrongBackendIntent, err := mutateJSONObject(intentJSON, func(value map[string]any) error {
		transitions, ok := value["transitions"].([]any)
		if !ok || len(transitions) == 0 {
			return fmt.Errorf("generated client-root intent has no transitions")
		}
		transition, ok := transitions[0].(map[string]any)
		if !ok {
			return fmt.Errorf("generated client-root transition is invalid")
		}
		if backend == maltcid.BackendKindKZG {
			transition["backend"] = string(maltcid.BackendKindIPA)
		} else {
			transition["backend"] = string(maltcid.BackendKindKZG)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	appendInvalid(prefix+"wrong-backend.reject", "wrong_backend", viewJSON, wrongBackendIntent)

	unknownFieldIntent, err := mutateJSONObject(intentJSON, func(value map[string]any) error {
		value["unknown"] = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	appendInvalid(prefix+"unknown-field.reject", "strict_json", viewJSON, unknownFieldIntent)
	return vectors, nil
}

func clientRootScheme(backend maltcid.BackendKind) (commitment.IndexCommitment, error) {
	switch backend {
	case maltcid.BackendKindKZG:
		return kzg.NewScheme()
	case maltcid.BackendKindIPA:
		return ipa.NewScheme()
	default:
		return nil, fmt.Errorf("unsupported client-root conformance backend %q", backend)
	}
}

func clientRootInput(ctx context.Context, backend maltcid.BackendKind, scheme commitment.IndexCommitment, baseVersion uint8) (mutation.UpdateView, mutation.SemanticIntent, error) {
	semantic, err := mapradix.NewMapForVersion(scheme, materialmemory.New(true), baseVersion)
	if err != nil {
		return mutation.UpdateView{}, mutation.SemanticIntent{}, err
	}
	before, err := rawCID("client-root-before-" + string(backend))
	if err != nil {
		return mutation.UpdateView{}, mutation.SemanticIntent{}, err
	}
	after, err := rawCID("client-root-after-" + string(backend))
	if err != nil {
		return mutation.UpdateView{}, mutation.SemanticIntent{}, err
	}
	root, err := semantic.Commit(ctx, "client-root-conformance-v1", mapping.NewViewFrom(map[string]cid.Cid{"file": before}))
	if err != nil {
		return mutation.UpdateView{}, mutation.SemanticIntent{}, err
	}
	coordinate, err := arcset.NewMapCoordinate("file")
	if err != nil {
		return mutation.UpdateView{}, mutation.SemanticIntent{}, err
	}
	entries, err := arcset.NewCanonicalArcSet(arcset.KindMap, []arcset.ArcEntry{{
		Coordinate: coordinate, Target: arcset.NewCASTarget(before),
	}})
	if err != nil {
		return mutation.UpdateView{}, mutation.SemanticIntent{}, err
	}
	view, err := mutation.NormalizeUpdateView(mutation.UpdateView{
		Profile: mutation.UpdateViewProfile, StateProfile: mutation.StatefulCompleteVectorsProfile,
		BaseRoot: root, Bounds: mutation.UpdateViewBounds{MaxObjects: 8, MaxTotalEntries: 64, MaxDepth: 8},
		Objects: []mutation.UpdateObject{{ObjectID: "root", Root: root, Kind: arcset.KindMap, Entries: entries}},
	})
	if err != nil {
		return mutation.UpdateView{}, mutation.SemanticIntent{}, err
	}
	beforeTarget := arcset.NewCASTarget(before)
	afterTarget := arcset.NewCASTarget(after)
	intent, err := mutation.NormalizeSemanticIntent(view, mutation.SemanticIntent{
		Profile: mutation.SemanticIntentProfile, BaseRoot: root, TopOutputID: "root-output",
		Transitions: []mutation.IntentTransition{{
			ID: "root-output", ObjectID: "root", OldRoot: root, Kind: arcset.KindMap, Backend: backend,
			Changes: []mutation.IntentChange{{Coordinate: coordinate, Before: &beforeTarget, After: &afterTarget}},
		}},
	})
	if err != nil {
		return mutation.UpdateView{}, mutation.SemanticIntent{}, err
	}
	return view, intent, nil
}

func mutateJSONObject(raw json.RawMessage, mutate func(map[string]any) error) (json.RawMessage, error) {
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	if err := mutate(value); err != nil {
		return nil, err
	}
	return json.Marshal(value)
}

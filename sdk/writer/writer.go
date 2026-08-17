// Package writer implements the application-neutral client-root computation
// path. It verifies a bounded complete update view, normalizes an output-free
// dependency graph, computes every changed semantic object bottom-up, and
// returns an exact client-root bundle. Persistence, publication, and trust
// promotion remain outside this package.
package writer

import (
	"context"
	"encoding/binary"
	"fmt"
	"slices"
	"time"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	materializer "github.com/dewebprotocol/malt-core/auth/arcset/materializer"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/semantic/list"
	"github.com/dewebprotocol/malt-core/auth/semantic/mapping"
	runtimegraph "github.com/dewebprotocol/malt-core/graph/runtime"
	"github.com/dewebprotocol/malt-core/mutation"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

// Runtime owns backend implementations and caller-supplied in-memory or
// persistent-free materialization used for local computation. The materializer
// is not an ArcTable and no result is durable until a service accepts it.
type Runtime struct {
	store        materializer.MutableStore
	graphs       map[maltcid.BackendKind]*runtimegraph.RuntimeGraph
	legacyGraphs map[maltcid.BackendKind]*runtimegraph.RuntimeGraph
}

// VerifiedUpdateView is a normalized view whose complete logical vectors have
// independently recomputed every declared old root in this runtime.
type VerifiedUpdateView struct {
	View         mutation.UpdateView
	runtime      *Runtime
	digest       [32]byte
	workingRoots map[string]cid.Cid
}

// ComputeResult carries both the exact submission bundle and the complete next
// view retained by a long-lived client session.
type ComputeResult struct {
	Bundle          mutation.ClientRootBundle
	Materialization mutation.ClientRootMaterialization
	NextView        mutation.UpdateView
	Metrics         ComputeMetrics
	seal            computeResultSeal
}

type computeResultSeal struct {
	runtime        *Runtime
	bundleDigest   [32]byte
	nextViewDigest [32]byte
	workingRoots   map[string]cid.Cid
}

// ComputeMetrics separates the client-local phases required by writer
// evaluation. Durations cover only local SDK work; payload hashing/upload,
// network submission, Gateway replay, and persistence stay caller-owned.
// CommitmentUpdateNS is a nested subphase of RootComputationNS and must not be
// added to it in a stacked breakdown. All other fields are disjoint phases.
type ComputeMetrics struct {
	ViewNormalizationNS    uint64 `json:"view_normalization_ns"`
	IntentNormalizationNS  uint64 `json:"intent_normalization_ns"`
	DigestNS               uint64 `json:"digest_ns"`
	CommitmentUpdateNS     uint64 `json:"commitment_update_ns"`
	RootComputationNS      uint64 `json:"root_computation_ns"`
	ExpectedRootEncodingNS uint64 `json:"expected_root_encoding_ns"`
	BundleValidationNS     uint64 `json:"bundle_validation_ns"`
	NextViewNS             uint64 `json:"next_view_ns"`
	TotalNS                uint64 `json:"total_ns"`
}

// NewRuntime creates a client writer over the narrow materializer capability.
// Callers normally provide the branching in-memory reference materializer;
// SDK code does not choose persistence policy.
func NewRuntime(store materializer.MutableStore, schemes map[maltcid.BackendKind]commitment.IndexCommitment) (*Runtime, error) {
	if store == nil {
		return nil, fmt.Errorf("client writer materializer is nil")
	}
	branching, ok := store.(materializer.BranchingStore)
	if !ok || !branching.SupportsConcurrentBranches() {
		return nil, fmt.Errorf("client writer requires a branching materializer for speculative candidates")
	}
	if len(schemes) == 0 {
		return nil, fmt.Errorf("client writer has no commitment backends")
	}
	runtime := &Runtime{
		store:        store,
		graphs:       make(map[maltcid.BackendKind]*runtimegraph.RuntimeGraph, len(schemes)),
		legacyGraphs: make(map[maltcid.BackendKind]*runtimegraph.RuntimeGraph, len(schemes)),
	}
	for _, backend := range []maltcid.BackendKind{maltcid.BackendKindKZG, maltcid.BackendKindIPA} {
		scheme, ok := schemes[backend]
		if !ok {
			continue
		}
		if scheme == nil {
			return nil, fmt.Errorf("client writer %s backend is nil", backend)
		}
		graph, err := runtimegraph.NewGraph(
			"client-root-"+string(backend),
			store,
			runtimegraph.WithCommitmentBackend(backend, scheme),
			runtimegraph.WithDefaultCommitmentBackend(backend),
		)
		if err != nil {
			return nil, fmt.Errorf("create client writer %s backend: %w", backend, err)
		}
		runtime.graphs[backend] = graph
		legacyGraph, err := runtimegraph.NewGraph(
			"client-root-legacy-"+string(backend),
			store,
			runtimegraph.WithCommitmentBackend(backend, scheme),
			runtimegraph.WithDefaultCommitmentBackend(backend),
			runtimegraph.WithMALTVersion(maltcid.LegacyMALTVersionID),
		)
		if err != nil {
			return nil, fmt.Errorf("create legacy client writer %s backend: %w", backend, err)
		}
		runtime.legacyGraphs[backend] = legacyGraph
	}
	if len(runtime.graphs) != len(schemes) || len(runtime.legacyGraphs) != len(schemes) {
		return nil, fmt.Errorf("client writer schemes contain an unsupported backend")
	}
	return runtime, nil
}

// VerifyUpdateView recomputes every complete logical vector and seeds the
// local semantic materialization required for subsequent incremental updates.
func (r *Runtime) VerifyUpdateView(ctx context.Context, view mutation.UpdateView) (VerifiedUpdateView, error) {
	if r == nil {
		return VerifiedUpdateView{}, fmt.Errorf("client writer runtime is nil")
	}
	canonical, err := mutation.NormalizeUpdateView(view)
	if err != nil {
		return VerifiedUpdateView{}, err
	}
	workingRoots := make(map[string]cid.Cid, len(canonical.Objects))
	for _, object := range canonical.Objects {
		if err := ctx.Err(); err != nil {
			return VerifiedUpdateView{}, err
		}
		backend := maltcid.BackendKindOf(object.Root)
		currentGraph, ok := r.graphs[backend]
		if !ok {
			return VerifiedUpdateView{}, fmt.Errorf("update object %q requires unavailable backend %q", object.ObjectID, backend)
		}
		verificationGraph := currentGraph
		switch version := maltcid.VersionIDOf(object.Root); version {
		case maltcid.MALTVersionID:
		case maltcid.LegacyMALTVersionID:
			verificationGraph = r.legacyGraphs[backend]
		default:
			return VerifiedUpdateView{}, fmt.Errorf("update object %q uses unsupported MALT version %d", object.ObjectID, version)
		}
		recomputed, err := commitCompleteObject(ctx, verificationGraph, objectScope(object.ObjectID), object)
		if err != nil {
			return VerifiedUpdateView{}, fmt.Errorf("verify update object %q: %w", object.ObjectID, err)
		}
		if !recomputed.Equals(object.Root) {
			return VerifiedUpdateView{}, fmt.Errorf("verify update object %q: recomputed root %s does not match declared root %s", object.ObjectID, recomputed, object.Root)
		}
		workingRoot := recomputed
		if verificationGraph != currentGraph {
			workingRoot, err = commitCompleteObject(ctx, currentGraph, objectScope(object.ObjectID), object)
			if err != nil {
				return VerifiedUpdateView{}, fmt.Errorf("migrate update object %q materialization: %w", object.ObjectID, err)
			}
		}
		logical, err := completeObjectArcSet(object)
		if err != nil {
			return VerifiedUpdateView{}, fmt.Errorf("verify update object %q: %w", object.ObjectID, err)
		}
		if err := r.store.Update(ctx, objectScope(object.ObjectID), recomputed, cid.Undef, logical); err != nil {
			return VerifiedUpdateView{}, fmt.Errorf("seed update object %q: %w", object.ObjectID, err)
		}
		if !workingRoot.Equals(recomputed) {
			if err := r.store.Update(ctx, objectScope(object.ObjectID), workingRoot, cid.Undef, logical); err != nil {
				return VerifiedUpdateView{}, fmt.Errorf("seed migrated update object %q: %w", object.ObjectID, err)
			}
		}
		workingRoots[object.ObjectID] = workingRoot
	}
	digest, err := canonical.Digest()
	if err != nil {
		return VerifiedUpdateView{}, fmt.Errorf("digest verified update view: %w", err)
	}
	return VerifiedUpdateView{View: canonical, runtime: r, digest: digest, workingRoots: workingRoots}, nil
}

// ComputeBundle applies a normalized intent bottom-up and returns the exact
// candidate plus every intermediate output. Literal CAS post-images are
// collected into PayloadCIDs for service-side existence checks.
func (r *Runtime) ComputeBundle(ctx context.Context, operationID string, verified VerifiedUpdateView, intent mutation.SemanticIntent) (ComputeResult, error) {
	totalStart := time.Now()
	if r == nil {
		return ComputeResult{}, fmt.Errorf("client writer runtime is nil")
	}
	metrics := ComputeMetrics{}
	phaseStart := time.Now()
	view, err := mutation.NormalizeUpdateView(verified.View)
	if err != nil {
		return ComputeResult{}, err
	}
	metrics.ViewNormalizationNS = writerDurationNS(time.Since(phaseStart))
	phaseStart = time.Now()
	normalized, err := mutation.NormalizeSemanticIntent(view, intent)
	if err != nil {
		return ComputeResult{}, err
	}
	metrics.IntentNormalizationNS = writerDurationNS(time.Since(phaseStart))
	phaseStart = time.Now()
	viewDigest, err := view.Digest()
	if err != nil {
		return ComputeResult{}, err
	}
	if verified.runtime != r || verified.digest != viewDigest {
		return ComputeResult{}, fmt.Errorf("verified update view seal does not match this runtime or its canonical contents")
	}
	intentDigest, err := normalized.Digest()
	if err != nil {
		return ComputeResult{}, err
	}
	metrics.DigestNS = writerDurationNS(time.Since(phaseStart))

	phaseStart = time.Now()
	objects := make(map[string]mutation.UpdateObject, len(view.Objects)+len(normalized.Transitions))
	workingRoots := make(map[string]cid.Cid, len(verified.workingRoots)+len(normalized.Transitions))
	for _, object := range view.Objects {
		objects[object.ObjectID] = object
		workingRoot, ok := verified.workingRoots[object.ObjectID]
		if !ok || !workingRoot.Defined() {
			return ComputeResult{}, fmt.Errorf("verified update object %q has no working root", object.ObjectID)
		}
		workingRoots[object.ObjectID] = workingRoot
	}
	outputRoots := make(map[string]cid.Cid, len(normalized.Transitions))
	outputs := make([]mutation.TransitionOutput, 0, len(normalized.Transitions))
	materializations := make([]mutation.MapMaterialization, 0, len(normalized.Transitions))
	payloadSet := make(map[string]cid.Cid)
	for _, transition := range normalized.Transitions {
		if err := ctx.Err(); err != nil {
			return ComputeResult{}, err
		}
		graph, ok := r.graphs[transition.Backend]
		if !ok {
			return ComputeResult{}, fmt.Errorf("transition %q requires unavailable backend %q", transition.ID, transition.Backend)
		}
		changes, err := resolveChanges(transition, outputRoots, payloadSet)
		if err != nil {
			return ComputeResult{}, err
		}
		delta, err := arcset.NewCanonicalArcDelta(transition.Kind, changes)
		if err != nil {
			return ComputeResult{}, fmt.Errorf("transition %q delta: %w", transition.ID, err)
		}
		commitmentStarted := time.Now()
		workingRoot := cid.Undef
		if transition.OldRoot.Defined() {
			var ok bool
			workingRoot, ok = workingRoots[transition.ObjectID]
			if !ok || !workingRoot.Defined() {
				return ComputeResult{}, fmt.Errorf("transition %q has no verified working root", transition.ID)
			}
		}
		receipt, err := graph.Writer().Apply(ctx, objectScope(transition.ObjectID), mutation.SemanticMutation{
			BaseRoot: view.BaseRoot,
			Deltas: []mutation.ArcSetDelta{{
				Object:  workingRoot,
				Kind:    transition.Kind,
				Changes: delta,
				Commit:  transition.Commit,
			}},
		})
		if err != nil {
			return ComputeResult{}, fmt.Errorf("compute transition %q: %w", transition.ID, err)
		}
		commitmentDuration := writerDurationNS(time.Since(commitmentStarted))
		if ^uint64(0)-metrics.CommitmentUpdateNS < commitmentDuration {
			return ComputeResult{}, fmt.Errorf("client writer commitment timing overflow")
		}
		metrics.CommitmentUpdateNS += commitmentDuration
		if maltcid.BackendKindOf(receipt.NewRoot) != transition.Backend {
			return ComputeResult{}, fmt.Errorf("compute transition %q returned backend %q, want %q", transition.ID, maltcid.BackendKindOf(receipt.NewRoot), transition.Backend)
		}
		outputRoots[transition.ID] = receipt.NewRoot
		workingRoots[transition.ObjectID] = receipt.NewRoot
		outputs = append(outputs, mutation.TransitionOutput{TransitionID: transition.ID, Root: receipt.NewRoot})
		postEntries, err := applyCompleteVector(objects[transition.ObjectID].Entries, transition.Kind, changes)
		if err != nil {
			return ComputeResult{}, fmt.Errorf("retain transition %q: %w", transition.ID, err)
		}
		objects[transition.ObjectID] = mutation.UpdateObject{
			ObjectID: transition.ObjectID,
			Root:     receipt.NewRoot,
			Kind:     transition.Kind,
			Entries:  postEntries,
			Commit:   transition.Commit,
		}
		if transition.Kind == arcset.KindMap {
			exporter, ok := graph.Semantic().(mapping.MaterializationExporter)
			if !ok {
				return ComputeResult{}, fmt.Errorf("transition %q backend does not export map materialization", transition.ID)
			}
			postView, err := mapViewFromEntries(postEntries)
			if err != nil {
				return ComputeResult{}, fmt.Errorf("materialize transition %q logical view: %w", transition.ID, err)
			}
			entries, err := exporter.ExportMaterialization(ctx, objectScope(transition.ObjectID), receipt.NewRoot, postView)
			if err != nil {
				return ComputeResult{}, fmt.Errorf("materialize transition %q: %w", transition.ID, err)
			}
			materializations = append(materializations, mutation.MapMaterialization{
				TransitionID: transition.ID, Root: receipt.NewRoot, Entries: entries,
			})
		}
	}
	candidate := outputRoots[normalized.TopOutputID]
	payloads := make([]cid.Cid, 0, len(payloadSet))
	for _, payload := range payloadSet {
		payloads = append(payloads, payload)
	}
	slices.SortFunc(payloads, func(a, b cid.Cid) int { return stringCompareBytes(a.Bytes(), b.Bytes()) })
	metrics.RootComputationNS = writerDurationNS(time.Since(phaseStart))
	phaseStart = time.Now()
	expectedRoot := candidate.String()
	if expectedRoot == "" {
		return ComputeResult{}, fmt.Errorf("client writer candidate root encoding is empty")
	}
	metrics.ExpectedRootEncodingNS = writerDurationNS(time.Since(phaseStart))
	phaseStart = time.Now()
	bundle, err := mutation.NewClientRootBundle(mutation.ClientRootBundle{
		Profile:      mutation.ClientRootBundleProfile,
		OperationID:  operationID,
		View:         view,
		Intent:       normalized,
		Outputs:      outputs,
		Candidate:    candidate,
		PayloadCIDs:  payloads,
		ViewDigest:   viewDigest,
		IntentDigest: intentDigest,
	})
	if err != nil {
		return ComputeResult{}, err
	}
	bundleDigest, err := bundle.Digest()
	if err != nil {
		return ComputeResult{}, fmt.Errorf("seal client-root bundle: %w", err)
	}
	materialization, err := mutation.NewClientRootMaterialization(bundle, mutation.ClientRootMaterialization{
		Profile: mutation.ClientRootMaterializationProfile,
		Maps:    materializations,
	})
	if err != nil {
		return ComputeResult{}, err
	}
	metrics.BundleValidationNS = writerDurationNS(time.Since(phaseStart))
	phaseStart = time.Now()
	next, err := nextReachableView(view, candidate, objects)
	if err != nil {
		return ComputeResult{}, err
	}
	nextViewDigest, err := next.Digest()
	if err != nil {
		return ComputeResult{}, fmt.Errorf("seal retained next view: %w", err)
	}
	nextWorkingRoots, err := workingRootsForView(next, workingRoots)
	if err != nil {
		return ComputeResult{}, fmt.Errorf("seal retained working roots: %w", err)
	}
	metrics.NextViewNS = writerDurationNS(time.Since(phaseStart))
	metrics.TotalNS = writerDurationNS(time.Since(totalStart))
	return ComputeResult{
		Bundle: bundle, Materialization: materialization, NextView: next, Metrics: metrics,
		seal: computeResultSeal{
			runtime: r, bundleDigest: bundleDigest, nextViewDigest: nextViewDigest,
			workingRoots: nextWorkingRoots,
		},
	}, nil
}

func workingRootsForView(view mutation.UpdateView, roots map[string]cid.Cid) (map[string]cid.Cid, error) {
	selected := make(map[string]cid.Cid, len(view.Objects))
	for _, object := range view.Objects {
		root, ok := roots[object.ObjectID]
		if !ok || !root.Defined() {
			return nil, fmt.Errorf("update object %q has no working root", object.ObjectID)
		}
		if maltcid.VersionIDOf(root) != maltcid.MALTVersionID ||
			maltcid.BackendKindOf(root) != maltcid.BackendKindOf(object.Root) ||
			maltcid.SemanticKindOf(root) != maltcid.SemanticKindOf(object.Root) {
			return nil, fmt.Errorf("update object %q working root profile does not match its retained root", object.ObjectID)
		}
		selected[object.ObjectID] = root
	}
	return selected, nil
}

func mapViewFromEntries(entries *arcset.CanonicalArcSet) (mapping.View, error) {
	if entries == nil || entries.Kind() != arcset.KindMap {
		return nil, fmt.Errorf("complete entries must be a canonical map")
	}
	values := make(map[arcset.Path]cid.Cid, entries.Len())
	for _, entry := range entries.Entries() {
		values[arcset.CanonicalizePath(entry.Coordinate.String())] = entry.Target.CID()
	}
	return mapping.NewViewFromPaths(values), nil
}

func commitCompleteObject(ctx context.Context, graph *runtimegraph.RuntimeGraph, scope string, object mutation.UpdateObject) (cid.Cid, error) {
	switch object.Kind {
	case arcset.KindMap:
		entries := make(map[arcset.Path]cid.Cid, object.Entries.Len())
		for _, entry := range object.Entries.Entries() {
			entries[arcset.CanonicalizePath(entry.Coordinate.String())] = entry.Target.CID()
		}
		return graph.Semantic().Commit(ctx, scope, mapping.NewViewFromPaths(entries))
	case arcset.KindList:
		values, err := listValues(object.Entries)
		if err != nil {
			return cid.Undef, err
		}
		if object.Commit.FixedList == nil {
			return graph.ListSemantic().Commit(ctx, scope, list.NewViewFromSlice(values))
		}
		fixed, ok := graph.ListSemantic().(list.FixedWidthCommitter)
		if !ok {
			return cid.Undef, fmt.Errorf("list backend does not support fixed-width commits")
		}
		return fixed.CommitFixed(ctx, scope, values, object.Commit.FixedList.ChunkSize, object.Commit.FixedList.TotalSize)
	default:
		return cid.Undef, fmt.Errorf("unsupported object kind %q", object.Kind)
	}
}

func completeObjectArcSet(object mutation.UpdateObject) (arcset.ArcSet, error) {
	values := make(map[arcset.Path]cid.Cid, object.Entries.Len())
	for _, entry := range object.Entries.Entries() {
		var path arcset.Path
		switch object.Kind {
		case arcset.KindMap:
			path = arcset.CanonicalizePath(entry.Coordinate.String())
		case arcset.KindList:
			path = arcset.CanonicalizePath(entry.Coordinate.String())
		default:
			return nil, fmt.Errorf("unsupported object kind %q", object.Kind)
		}
		values[path] = entry.Target.CID()
	}
	return arcset.NewArcSetFromPaths(values)
}

func resolveChanges(transition mutation.IntentTransition, outputs map[string]cid.Cid, payloads map[string]cid.Cid) ([]arcset.ArcChange, error) {
	changes := make([]arcset.ArcChange, len(transition.Changes))
	for index, change := range transition.Changes {
		resolved := arcset.ArcChange{Coordinate: change.Coordinate, Before: change.Before, After: change.After}
		if change.OutputID != "" {
			root, ok := outputs[change.OutputID]
			if !ok {
				return nil, fmt.Errorf("transition %q consumes unavailable output %q", transition.ID, change.OutputID)
			}
			var target arcset.TargetRef
			switch change.OutputKind {
			case arcset.TargetKindMap:
				target = arcset.NewMapTarget(root)
			case arcset.TargetKindList:
				target = arcset.NewListTarget(root)
			default:
				return nil, fmt.Errorf("transition %q has invalid output kind %q", transition.ID, change.OutputKind)
			}
			resolved.After = &target
		} else if change.After != nil && !isSemanticTarget(*change.After) {
			payloads[change.After.CID().KeyString()] = change.After.CID()
		}
		changes[index] = resolved
	}
	return changes, nil
}

func applyCompleteVector(current *arcset.CanonicalArcSet, kind arcset.Kind, changes []arcset.ArcChange) (*arcset.CanonicalArcSet, error) {
	entries := make(map[string]arcset.ArcEntry)
	if current != nil {
		for _, entry := range current.Entries() {
			entries[string(entry.Coordinate.Bytes())] = entry
		}
	}
	for _, change := range changes {
		key := string(change.Coordinate.Bytes())
		if change.After == nil {
			delete(entries, key)
			continue
		}
		entries[key] = arcset.ArcEntry{Coordinate: change.Coordinate, Target: *change.After}
	}
	values := make([]arcset.ArcEntry, 0, len(entries))
	for _, entry := range entries {
		values = append(values, entry)
	}
	return arcset.NewCanonicalArcSet(kind, values)
}

func nextReachableView(previous mutation.UpdateView, candidate cid.Cid, objects map[string]mutation.UpdateObject) (mutation.UpdateView, error) {
	ordered := make([]mutation.UpdateObject, 0, len(objects))
	for _, object := range objects {
		ordered = append(ordered, object)
	}
	slices.SortFunc(ordered, func(a, b mutation.UpdateObject) int {
		switch {
		case a.ObjectID < b.ObjectID:
			return -1
		case a.ObjectID > b.ObjectID:
			return 1
		default:
			return 0
		}
	})
	byRoot := make(map[string]mutation.UpdateObject, len(objects))
	for _, object := range ordered {
		rootKey := object.Root.KeyString()
		if existing, ok := byRoot[rootKey]; ok {
			return mutation.UpdateView{}, fmt.Errorf("retained objects %q and %q converge to root %s", existing.ObjectID, object.ObjectID, object.Root)
		}
		byRoot[rootKey] = object
	}
	rootObject, ok := byRoot[candidate.KeyString()]
	if !ok {
		return mutation.UpdateView{}, fmt.Errorf("candidate root has no retained complete vector")
	}
	reachable := make(map[string]mutation.UpdateObject)
	var visit func(mutation.UpdateObject) error
	visit = func(object mutation.UpdateObject) error {
		if _, seen := reachable[object.ObjectID]; seen {
			return nil
		}
		reachable[object.ObjectID] = object
		for _, entry := range object.Entries.Entries() {
			if !isSemanticTarget(entry.Target) {
				continue
			}
			child, exists := byRoot[entry.Target.CID().KeyString()]
			if !exists {
				return fmt.Errorf("retained object %q references missing child %s", object.ObjectID, entry.Target.CID())
			}
			if err := visit(child); err != nil {
				return err
			}
		}
		return nil
	}
	if err := visit(rootObject); err != nil {
		return mutation.UpdateView{}, err
	}
	next := mutation.UpdateView{
		Profile: previous.Profile, StateProfile: previous.StateProfile,
		BaseRoot: candidate, Bounds: previous.Bounds,
		Objects: make([]mutation.UpdateObject, 0, len(reachable)),
	}
	for _, object := range reachable {
		next.Objects = append(next.Objects, object)
	}
	return mutation.NormalizeUpdateView(next)
}

func listValues(entries *arcset.CanonicalArcSet) ([]cid.Cid, error) {
	values := make([]cid.Cid, entries.Len())
	for index, entry := range entries.Entries() {
		raw := entry.Coordinate.Bytes()
		if len(raw) != 8 || binary.BigEndian.Uint64(raw) != uint64(index) {
			return nil, fmt.Errorf("list vector is sparse or out of order at %q", entry.Coordinate.String())
		}
		values[index] = entry.Target.CID()
	}
	return values, nil
}

func isSemanticTarget(target arcset.TargetRef) bool {
	if target.Kind() == arcset.TargetKindMap || target.Kind() == arcset.TargetKindList {
		return true
	}
	return maltcid.SemanticKindOf(target.CID()) != maltcid.SemanticKindUnknown
}

func objectScope(objectID string) string {
	return "client-root/v1/" + objectID
}

func stringCompareBytes(a, b []byte) int {
	for index := 0; index < len(a) && index < len(b); index++ {
		if a[index] < b[index] {
			return -1
		}
		if a[index] > b[index] {
			return 1
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	default:
		return 0
	}
}

func writerDurationNS(value time.Duration) uint64 {
	if value <= 0 {
		return 0
	}
	return uint64(value)
}

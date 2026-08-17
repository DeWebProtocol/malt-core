package writer

import (
	"context"
	"fmt"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	"github.com/dewebprotocol/malt-core/auth/semantic/mapping"
	"github.com/dewebprotocol/malt-core/mutation"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

// BootstrapMap constructs and verifies the canonical empty map base entirely
// inside the client writer. The returned root-bound state lets an untrusted
// service validate and materialize that base without calling Commit.
func (r *Runtime) BootstrapMap(ctx context.Context, backend maltcid.BackendKind, bounds mutation.UpdateViewBounds) (VerifiedUpdateView, mutation.MapStateMaterialization, error) {
	if r == nil {
		return VerifiedUpdateView{}, mutation.MapStateMaterialization{}, fmt.Errorf("client writer runtime is nil")
	}
	graph, ok := r.graphs[backend]
	if !ok {
		return VerifiedUpdateView{}, mutation.MapStateMaterialization{}, fmt.Errorf("client writer backend %q is unavailable", backend)
	}
	emptyEntries, err := arcset.NewCanonicalArcSet(arcset.KindMap, nil)
	if err != nil {
		return VerifiedUpdateView{}, mutation.MapStateMaterialization{}, err
	}
	emptyView := mapping.NewViewFromPaths(map[arcset.Path]cid.Cid{})
	root, err := graph.Semantic().Commit(ctx, objectScope("root"), emptyView)
	if err != nil {
		return VerifiedUpdateView{}, mutation.MapStateMaterialization{}, fmt.Errorf("commit client bootstrap map: %w", err)
	}
	view, err := mutation.NormalizeUpdateView(mutation.UpdateView{
		Profile: mutation.UpdateViewProfile, StateProfile: mutation.StatefulCompleteVectorsProfile,
		BaseRoot: root, Bounds: bounds,
		Objects: []mutation.UpdateObject{{ObjectID: "root", Root: root, Kind: arcset.KindMap, Entries: emptyEntries}},
	})
	if err != nil {
		return VerifiedUpdateView{}, mutation.MapStateMaterialization{}, fmt.Errorf("normalize client bootstrap view: %w", err)
	}
	verified, err := r.VerifyUpdateView(ctx, view)
	if err != nil {
		return VerifiedUpdateView{}, mutation.MapStateMaterialization{}, fmt.Errorf("verify client bootstrap view: %w", err)
	}
	exporter, ok := graph.Semantic().(mapping.MaterializationExporter)
	if !ok {
		return VerifiedUpdateView{}, mutation.MapStateMaterialization{}, fmt.Errorf("client bootstrap backend does not export map materialization")
	}
	entries, err := exporter.ExportMaterialization(ctx, objectScope("root"), root, emptyView)
	if err != nil {
		return VerifiedUpdateView{}, mutation.MapStateMaterialization{}, fmt.Errorf("export client bootstrap materialization: %w", err)
	}
	return verified, mutation.MapStateMaterialization{Root: root, Entries: entries}, nil
}

// BootstrapMap replaces the session with a browser-computed canonical empty
// map base. No service-provided update view participates in this bootstrap.
func (s *Session) BootstrapMap(ctx context.Context, backend maltcid.BackendKind, bounds mutation.UpdateViewBounds) (mutation.UpdateView, mutation.MapStateMaterialization, error) {
	if s == nil || s.runtime == nil {
		return mutation.UpdateView{}, mutation.MapStateMaterialization{}, fmt.Errorf("client writer session is nil")
	}
	verified, materialization, err := s.runtime.BootstrapMap(ctx, backend, bounds)
	if err != nil {
		return mutation.UpdateView{}, mutation.MapStateMaterialization{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.current = verified
	s.loaded = true
	return verified.View, materialization, nil
}

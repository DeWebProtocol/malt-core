package runtimegraph

import (
	"context"
	"fmt"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	structure "github.com/dewebprotocol/malt-core/auth/semantic"
	"github.com/dewebprotocol/malt-core/auth/semantic/list"
	"github.com/dewebprotocol/malt-core/auth/semantic/mapping"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

type mapBackendDispatcher struct {
	defaultBackend maltcid.BackendKind
	backends       map[maltcid.BackendKind]mapping.Semantics
}

func (d *mapBackendDispatcher) Commitment() *mapping.Commitment {
	return d.backends[d.defaultBackend].Commitment()
}

func (d *mapBackendDispatcher) Commit(ctx context.Context, namespace string, view mapping.View) (cid.Cid, error) {
	backend, err := d.defaultSemantics()
	if err != nil {
		return cid.Undef, err
	}
	return backend.Commit(ctx, namespace, view)
}

func (d *mapBackendDispatcher) Prove(ctx context.Context, namespace string, root cid.Cid, key arcset.Path) (mapping.Binding, structure.Proof, error) {
	backend, err := d.forRoot(root)
	if err != nil {
		return mapping.Binding{}, nil, err
	}
	return backend.Prove(ctx, namespace, root, key)
}

func (d *mapBackendDispatcher) Verify(root cid.Cid, key arcset.Path, expected mapping.Binding, proof structure.Proof) (bool, error) {
	backend, err := d.forRoot(root)
	if err != nil {
		return false, err
	}
	return backend.Verify(root, key, expected, proof)
}

func (d *mapBackendDispatcher) Update(ctx context.Context, namespace string, root cid.Cid, key arcset.Path, oldValue, newValue cid.Cid) (cid.Cid, error) {
	backend, err := d.forRoot(root)
	if err != nil {
		return cid.Undef, err
	}
	return backend.Update(ctx, namespace, root, key, oldValue, newValue)
}

func (d *mapBackendDispatcher) BatchUpdate(ctx context.Context, namespace string, root cid.Cid, updates []mapping.BatchUpdate) (cid.Cid, error) {
	backend, err := d.forRoot(root)
	if err != nil {
		return cid.Undef, err
	}
	return backend.BatchUpdate(ctx, namespace, root, updates)
}

func (d *mapBackendDispatcher) ExportMaterialization(ctx context.Context, namespace string, root cid.Cid, view mapping.View) (*arcset.CanonicalArcSet, error) {
	backend, err := d.forRoot(root)
	if err != nil {
		return nil, err
	}
	exporter, ok := backend.(mapping.MaterializationExporter)
	if !ok {
		return nil, fmt.Errorf("commitment backend %q does not export map materialization", maltcid.BackendKindOf(root))
	}
	return exporter.ExportMaterialization(ctx, namespace, root, view)
}

func (d *mapBackendDispatcher) defaultSemantics() (mapping.Semantics, error) {
	backend := d.backends[d.defaultBackend]
	if backend == nil {
		return nil, fmt.Errorf("default commitment backend %q is not registered", d.defaultBackend)
	}
	return backend, nil
}

func (d *mapBackendDispatcher) forRoot(root cid.Cid) (mapping.Semantics, error) {
	if !root.Defined() {
		return nil, fmt.Errorf("map root is undefined")
	}
	if kind := maltcid.SemanticKindOf(root); kind != maltcid.SemanticKindMap {
		return nil, fmt.Errorf("root %s has semantic kind %q, expected map", root, kind)
	}
	backendKind := maltcid.BackendKindOf(root)
	if backendKind == maltcid.BackendKindUnknown {
		return nil, fmt.Errorf("root %s does not encode a supported commitment backend", root)
	}
	backend := d.backends[backendKind]
	if backend == nil {
		return nil, fmt.Errorf("commitment backend %q is not registered for proving", backendKind)
	}
	return backend, nil
}

type listBackendDispatcher struct {
	defaultBackend maltcid.BackendKind
	backends       map[maltcid.BackendKind]list.MeasuredSemantics
}

func (d *listBackendDispatcher) Commitment() *list.Commitment {
	return d.backends[d.defaultBackend].Commitment()
}

func (d *listBackendDispatcher) Commit(ctx context.Context, namespace string, view list.View) (cid.Cid, error) {
	backend, err := d.defaultSemantics()
	if err != nil {
		return cid.Undef, err
	}
	return backend.Commit(ctx, namespace, view)
}

func (d *listBackendDispatcher) CommitFixed(ctx context.Context, namespace string, chunks []cid.Cid, chunkSize, totalSize uint64) (cid.Cid, error) {
	backend, err := d.defaultSemantics()
	if err != nil {
		return cid.Undef, err
	}
	fixed, ok := backend.(list.FixedWidthCommitter)
	if !ok {
		return cid.Undef, fmt.Errorf("default list backend %q does not support fixed measured commits", d.defaultBackend)
	}
	return fixed.CommitFixed(ctx, namespace, chunks, chunkSize, totalSize)
}

func (d *listBackendDispatcher) Prove(ctx context.Context, namespace string, root cid.Cid, index uint64) (list.Query, structure.Proof, error) {
	backend, err := d.forRoot(root)
	if err != nil {
		return list.Query{}, nil, err
	}
	return backend.Prove(ctx, namespace, root, index)
}

func (d *listBackendDispatcher) Verify(root cid.Cid, index uint64, expected list.Query, proof structure.Proof) (bool, error) {
	backend, err := d.forRoot(root)
	if err != nil {
		return false, err
	}
	return backend.Verify(root, index, expected, proof)
}

func (d *listBackendDispatcher) Replace(ctx context.Context, namespace string, root cid.Cid, index uint64, oldKey, newKey cid.Cid) (cid.Cid, error) {
	backend, err := d.forRoot(root)
	if err != nil {
		return cid.Undef, err
	}
	return backend.Replace(ctx, namespace, root, index, oldKey, newKey)
}

func (d *listBackendDispatcher) Append(ctx context.Context, namespace string, root cid.Cid, key cid.Cid) (cid.Cid, uint64, error) {
	backend, err := d.forRoot(root)
	if err != nil {
		return cid.Undef, 0, err
	}
	return backend.Append(ctx, namespace, root, key)
}

func (d *listBackendDispatcher) AppendFixed(ctx context.Context, namespace string, root cid.Cid, key cid.Cid, totalSize uint64) (cid.Cid, uint64, error) {
	backend, err := d.forRoot(root)
	if err != nil {
		return cid.Undef, 0, err
	}
	appender, ok := backend.(list.FixedWidthAppender)
	if !ok {
		return cid.Undef, 0, fmt.Errorf("list backend %q does not support fixed measured append", maltcid.BackendKindOf(root))
	}
	return appender.AppendFixed(ctx, namespace, root, key, totalSize)
}

func (d *listBackendDispatcher) Truncate(ctx context.Context, namespace string, root cid.Cid, newLen uint64) (cid.Cid, error) {
	backend, err := d.forRoot(root)
	if err != nil {
		return cid.Undef, err
	}
	return backend.Truncate(ctx, namespace, root, newLen)
}

func (d *listBackendDispatcher) ProveRange(ctx context.Context, namespace string, root cid.Cid, start uint64, end *uint64) (list.RangeResult, structure.Proof, error) {
	backend, err := d.forRoot(root)
	if err != nil {
		return list.RangeResult{}, nil, err
	}
	return backend.ProveRange(ctx, namespace, root, start, end)
}

func (d *listBackendDispatcher) VerifyRange(root cid.Cid, start uint64, end *uint64, expected list.RangeResult, proof structure.Proof) (bool, error) {
	backend, err := d.forRoot(root)
	if err != nil {
		return false, err
	}
	return backend.VerifyRange(root, start, end, expected, proof)
}

func (d *listBackendDispatcher) defaultSemantics() (list.MeasuredSemantics, error) {
	backend := d.backends[d.defaultBackend]
	if backend == nil {
		return nil, fmt.Errorf("default commitment backend %q is not registered", d.defaultBackend)
	}
	return backend, nil
}

func (d *listBackendDispatcher) forRoot(root cid.Cid) (list.MeasuredSemantics, error) {
	if !root.Defined() {
		return nil, fmt.Errorf("list root is undefined")
	}
	if kind := maltcid.SemanticKindOf(root); kind != maltcid.SemanticKindList {
		return nil, fmt.Errorf("root %s has semantic kind %q, expected list", root, kind)
	}
	backendKind := maltcid.BackendKindOf(root)
	if backendKind == maltcid.BackendKindUnknown {
		return nil, fmt.Errorf("root %s does not encode a supported commitment backend", root)
	}
	backend := d.backends[backendKind]
	if backend == nil {
		return nil, fmt.Errorf("commitment backend %q is not registered for proving", backendKind)
	}
	return backend, nil
}

func validateBackendOptions(options *Options) (maltcid.BackendKind, error) {
	if options.Scheme != nil {
		return maltcid.BackendKindUnknown, fmt.Errorf("WithCommitmentScheme cannot be combined with registered commitment backends")
	}
	if len(options.Backends) == 0 {
		return maltcid.BackendKindUnknown, fmt.Errorf("no commitment backends are registered")
	}
	for kind, scheme := range options.Backends {
		if kind == "" || kind == maltcid.BackendKindUnknown {
			return maltcid.BackendKindUnknown, fmt.Errorf("cannot register an unknown commitment backend")
		}
		if scheme == nil {
			return maltcid.BackendKindUnknown, fmt.Errorf("commitment backend %q is nil", kind)
		}
	}
	defaultBackend := options.DefaultBackend
	if (defaultBackend == "" || defaultBackend == maltcid.BackendKindUnknown) && len(options.Backends) == 1 {
		for kind := range options.Backends {
			defaultBackend = kind
		}
	}
	if defaultBackend == "" || defaultBackend == maltcid.BackendKindUnknown {
		return maltcid.BackendKindUnknown, fmt.Errorf("default commitment backend is required when multiple backends are registered")
	}
	if options.Backends[defaultBackend] == nil {
		return maltcid.BackendKindUnknown, fmt.Errorf("default commitment backend %q is not registered", defaultBackend)
	}
	return defaultBackend, nil
}

var (
	_ mapping.Semantics        = (*mapBackendDispatcher)(nil)
	_ list.MeasuredSemantics   = (*listBackendDispatcher)(nil)
	_ list.FixedWidthSemantics = (*listBackendDispatcher)(nil)
)

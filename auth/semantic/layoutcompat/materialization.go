package layoutcompat

import (
	"context"
	"fmt"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	"github.com/dewebprotocol/malt-core/auth/arcset/materializer"
	"github.com/dewebprotocol/malt-core/auth/arcset/materializer/encoded"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/semantic/mapping"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

type recordLookup struct {
	source   materializer.Lookup
	values   map[arcset.Path]cid.Cid
	consumed map[arcset.Path]cid.Cid
}

func (r *recordLookup) Get(ctx context.Context, scope string, root cid.Cid, path arcset.Path) (cid.Cid, error) {
	values, err := r.BatchGet(ctx, scope, root, []arcset.Path{path})
	if err != nil {
		return cid.Undef, err
	}
	value, ok := values[path]
	if !ok {
		return cid.Undef, materializer.ErrNotFound
	}
	return value, nil
}
func (r *recordLookup) BatchGet(ctx context.Context, scope string, root cid.Cid, paths []arcset.Path) (map[arcset.Path]cid.Cid, error) {
	values := make(map[arcset.Path]cid.Cid)
	var err error
	if r.source != nil {
		values, err = r.source.BatchGet(ctx, scope, root, paths)
		if err != nil {
			return nil, err
		}
	} else {
		for _, path := range paths {
			if value, ok := r.values[path]; ok {
				values[path] = value
			}
		}
	}
	requested := make(map[arcset.Path]bool, len(paths))
	for _, path := range paths {
		requested[path] = true
	}
	for path, value := range values {
		if !requested[path] {
			return nil, fmt.Errorf("unrequested materialization entry")
		}
		r.consumed[path] = value
	}
	return values, nil
}
func canonicalRecords(values map[arcset.Path]cid.Cid) (*arcset.CanonicalArcSet, error) {
	entries := make([]arcset.ArcEntry, 0, len(values))
	for path, value := range values {
		coordinate, err := arcset.NewMapCoordinate(path.String())
		if err != nil {
			return nil, err
		}
		entries = append(entries, arcset.ArcEntry{Coordinate: coordinate, Target: arcset.NewUnknownTarget(value)})
	}
	return arcset.NewCanonicalArcSet(arcset.KindMap, entries)
}
func (s *Prefix) ExportMaterialization(ctx context.Context, scope string, root cid.Cid, view mapping.View) (*arcset.CanonicalArcSet, error) {
	d, _, err := maltcid.ParseRoot(root)
	if err != nil {
		return nil, err
	}
	state, err := s.state(d, view)
	if err != nil {
		return nil, err
	}
	lookup := &recordLookup{source: s.store, consumed: make(map[arcset.Path]cid.Cid)}
	if err := s.engine.ValidateState(ctx, root, state, encoded.Nodes{Lookup: lookup, Scope: scope}); err != nil {
		return nil, err
	}
	return canonicalRecords(lookup.consumed)
}
func ValidateMaterialization(ctx context.Context, scheme commitment.IndexVerifier, root cid.Cid, view mapping.View, witness *arcset.CanonicalArcSet) error {
	if witness == nil || witness.Kind() != arcset.KindMap {
		return fmt.Errorf("materialization witness must be a canonical map")
	}
	e, p, err := Engine(scheme, nil)
	if err != nil {
		return err
	}
	d, _, err := maltcid.ParseRoot(root)
	if err != nil {
		return err
	}
	if d.Profile != p || d.Layout != maltcid.Prefix {
		return fmt.Errorf("materialization profile mismatch")
	}
	adapter := &Prefix{engine: e}
	state, err := adapter.state(d, view)
	if err != nil {
		return err
	}
	lookup := &recordLookup{values: make(map[arcset.Path]cid.Cid), consumed: make(map[arcset.Path]cid.Cid)}
	for _, entry := range witness.Entries() {
		lookup.values[arcset.Path(entry.Coordinate.String())] = entry.Target.CID()
	}
	if err := e.ValidateState(ctx, root, state, encoded.Nodes{Lookup: lookup}); err != nil {
		return err
	}
	if len(lookup.consumed) != len(lookup.values) {
		return fmt.Errorf("unreachable materialization entries")
	}
	return nil
}

package radix

import (
	"context"
	"fmt"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	"github.com/dewebprotocol/malt-core/auth/arcset/materializer"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/semantic/mapping"
	"github.com/dewebprotocol/malt-core/auth/semantic/nodegeometry"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

// RootBoundVerifier is the primitive capability required to validate a radix
// materialization against caller-supplied roots without recomputing them.
type RootBoundVerifier interface {
	commitment.IndexVerifier
	commitment.IndexRootProver
}

type materializationSource func(arcset.Path) (cid.Cid, bool, error)

type materializationWalker struct {
	ctx                   context.Context
	scheme                RootBoundVerifier
	geometry              nodegeometry.Geometry
	source                materializationSource
	consumed              map[arcset.Path]cid.Cid
	visiting              map[string]struct{}
	version               uint8
	backend               maltcid.BackendKind
	expectedBucketVersion bucketRefVersion
}

// ExportMaterialization returns the exact internal radix node and collision
// bucket entries needed to prove the supplied logical view at root. The
// exported state remains untrusted until ValidateMaterialization accepts it.
func (s *Map) ExportMaterialization(ctx context.Context, namespace string, root cid.Cid, view mapping.View) (*arcset.CanonicalArcSet, error) {
	if s == nil || s.materializer == nil || s.commitment == nil {
		return nil, fmt.Errorf("radix map is nil")
	}
	scheme, ok := s.commitment.Scheme().(RootBoundVerifier)
	if !ok {
		return nil, fmt.Errorf("commitment backend does not support root-bound materialization validation")
	}
	walker := &materializationWalker{
		ctx: ctx, scheme: scheme, geometry: s.geometry,
		consumed: make(map[arcset.Path]cid.Cid), visiting: make(map[string]struct{}),
	}
	walker.source = func(path arcset.Path) (cid.Cid, bool, error) {
		value, err := s.materializer.Get(ctx, namespace, cid.Undef, path)
		if err == nil {
			return value, true, nil
		}
		if materializer.IsNotFound(err) {
			return cid.Undef, false, nil
		}
		return cid.Undef, false, err
	}
	if err := walker.validate(root, view); err != nil {
		return nil, err
	}
	return canonicalMaterialization(walker.consumed)
}

// ValidateMaterialization validates an untrusted internal radix witness
// against root and the complete logical view. It invokes only ProveAtRoot;
// callers can therefore import client-computed roots without calling Commit.
func ValidateMaterialization(ctx context.Context, scheme RootBoundVerifier, root cid.Cid, view mapping.View, witness *arcset.CanonicalArcSet) error {
	if scheme == nil {
		return fmt.Errorf("root-bound commitment verifier is nil")
	}
	if witness == nil || witness.Kind() != arcset.KindMap {
		return fmt.Errorf("radix materialization witness must be a canonical map")
	}
	values := make(map[arcset.Path]cid.Cid, witness.Len())
	for _, entry := range witness.Entries() {
		path, err := arcset.NewPath(entry.Coordinate.String())
		if err != nil {
			return fmt.Errorf("invalid radix materialization coordinate: %w", err)
		}
		values[path] = entry.Target.CID()
	}
	geometry, err := nodegeometry.ForCapacity(scheme.MaxValues())
	if err != nil {
		return err
	}
	walker := &materializationWalker{
		ctx: ctx, scheme: scheme, geometry: geometry,
		consumed: make(map[arcset.Path]cid.Cid), visiting: make(map[string]struct{}),
		source: func(path arcset.Path) (cid.Cid, bool, error) {
			value, ok := values[path]
			return value, ok, nil
		},
	}
	if err := walker.validate(root, view); err != nil {
		return err
	}
	if len(walker.consumed) != len(values) {
		return fmt.Errorf("radix materialization witness contains unreachable entries")
	}
	return nil
}

func (w *materializationWalker) validate(root cid.Cid, view mapping.View) error {
	if err := w.ctx.Err(); err != nil {
		return err
	}
	if !root.Defined() {
		return fmt.Errorf("radix materialization root is undefined")
	}
	w.version = maltcid.VersionIDOf(root)
	w.backend = maltcid.BackendKindOf(root)
	var ok bool
	w.expectedBucketVersion, ok = bucketVersionForMALTVersion(w.version)
	if !ok || !matchesRadixRootProfile(root, w.version, w.backend) {
		return fmt.Errorf("radix materialization root has an unsupported map profile")
	}
	bindings, err := extractBindings(view)
	if err != nil {
		return err
	}
	return w.validateNode(root, bindings, 0)
}

func (w *materializationWalker) validateNode(root cid.Cid, bindings []leafBinding, depth int) error {
	if err := w.ctx.Err(); err != nil {
		return err
	}
	if !matchesRadixRootProfile(root, w.version, w.backend) {
		return fmt.Errorf("radix materialization contains a mixed-version or mixed-backend node")
	}
	if depth >= w.geometry.MapDepth(sha256Size) {
		return fmt.Errorf("radix materialization exceeds map depth")
	}
	key := root.KeyString()
	if _, exists := w.visiting[key]; exists {
		return fmt.Errorf("radix materialization contains a node cycle")
	}
	w.visiting[key] = struct{}{}
	defer delete(w.visiting, key)

	slots := make([]cid.Cid, w.geometry.NodeWidth())
	for index := range slots {
		path := nodeSlotPath(root, uint64(index))
		value, found, err := w.read(path)
		if err != nil {
			return err
		}
		if found {
			slots[index] = value
		}
	}
	if err := proveVectorAtRoot(w.scheme, root, slots); err != nil {
		return fmt.Errorf("radix node %s does not match its root: %w", root, err)
	}
	grouped, err := groupBindings(w.geometry, bindings, depth)
	if err != nil {
		return err
	}
	for index, slot := range slots {
		group := grouped[uint64(index)]
		if len(group) == 0 {
			if slot.Defined() {
				return fmt.Errorf("radix node has an unexpected slot %d", index)
			}
			continue
		}
		if !slot.Defined() {
			return fmt.Errorf("radix node is missing slot %d", index)
		}
		nextDepth := depth + 1
		switch {
		case len(group) == 1:
			expected, err := encodeLeafMarker(group[0].path, group[0].value)
			if err != nil {
				return err
			}
			if !slot.Equals(expected) {
				return fmt.Errorf("radix leaf marker mismatch at depth %d slot %d", depth, index)
			}
		case nextDepth >= w.geometry.MapDepth(sha256Size) || allSameDigest(group):
			bucketRoot, version, ok, err := decodeBucketRef(slot)
			if err != nil || !ok {
				return fmt.Errorf("radix collision bucket reference is invalid at depth %d slot %d", depth, index)
			}
			if err := w.validateBucket(bucketRoot, version, group); err != nil {
				return err
			}
		default:
			if err := w.validateNode(slot, group, nextDepth); err != nil {
				return err
			}
		}
	}
	return nil
}

func (w *materializationWalker) validateBucket(root cid.Cid, version bucketRefVersion, bindings []leafBinding) error {
	if version != w.expectedBucketVersion || !matchesRadixRootProfile(root, w.version, w.backend) {
		return fmt.Errorf("radix materialization collision bucket does not match the root profile")
	}
	if len(bindings) < 2 || len(bindings) > w.scheme.MaxValues() {
		return fmt.Errorf("radix collision bucket size is invalid")
	}
	countPath := bucketCountPath(root)
	countMarker, found, err := w.read(countPath)
	if err != nil {
		return err
	}
	expectedCount, err := encodeBucketCountMarker(uint64(len(bindings)))
	if err != nil {
		return err
	}
	if !found || !countMarker.Equals(expectedCount) {
		return fmt.Errorf("radix collision bucket count is invalid")
	}
	markers := make([]cid.Cid, len(bindings))
	for index, binding := range bindings {
		path := bucketEntryPath(root, uint64(index))
		marker, found, err := w.read(path)
		if err != nil {
			return err
		}
		expected, err := encodeLeafMarker(binding.path, binding.value)
		if err != nil {
			return err
		}
		if !found || !marker.Equals(expected) {
			return fmt.Errorf("radix collision bucket entry %d is invalid", index)
		}
		markers[index] = marker
	}
	vector := markers
	if version == bucketRefV2 {
		vector = bucketVector(markers, w.scheme.MaxValues())
	}
	if err := proveVectorAtRoot(w.scheme, root, vector); err != nil {
		return fmt.Errorf("radix collision bucket does not match its root: %w", err)
	}
	return nil
}

func (w *materializationWalker) read(path arcset.Path) (cid.Cid, bool, error) {
	value, found, err := w.source(path)
	if err != nil {
		return cid.Undef, false, err
	}
	if !found {
		return cid.Undef, false, nil
	}
	if !value.Defined() {
		return cid.Undef, false, fmt.Errorf("radix materialization contains an undefined target")
	}
	w.consumed[path] = value
	return value, true, nil
}

func proveVectorAtRoot(scheme RootBoundVerifier, root cid.Cid, values []cid.Cid) error {
	if len(values) == 0 {
		return fmt.Errorf("radix commitment vector is empty")
	}
	_, _, err := scheme.ProveAtRoot(root, cellsFromCIDs(values), 0)
	return err
}

func groupBindings(geometry nodegeometry.Geometry, bindings []leafBinding, depth int) (map[uint64][]leafBinding, error) {
	grouped := make(map[uint64][]leafBinding)
	for _, binding := range bindings {
		digit, ok := geometry.MapDigit(binding.digest[:], depth)
		if !ok {
			return nil, fmt.Errorf("invalid radix depth %d", depth)
		}
		grouped[digit] = append(grouped[digit], binding)
	}
	return grouped, nil
}

func canonicalMaterialization(values map[arcset.Path]cid.Cid) (*arcset.CanonicalArcSet, error) {
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

const sha256Size = 32

var _ mapping.MaterializationExporter = (*Map)(nil)

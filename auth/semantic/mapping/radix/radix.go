// Package radix implements a digest-keyed radix-map semantic above the
// primitive index commitment backends.
//
// This implementation uses the single-step commitment primitives from
// auth/semantic/mapping and combines them with storage access for multi-step
// radix tree traversal operations.
package radix

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	materializer "github.com/dewebprotocol/malt-core/auth/arcset/materializer"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/observation"
	"github.com/dewebprotocol/malt-core/auth/semantic"
	"github.com/dewebprotocol/malt-core/auth/semantic/mapping"
	"github.com/dewebprotocol/malt-core/auth/semantic/nodegeometry"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

const (
	leafPrefix        = "malt:map:radix:leaf:v1:"
	bucketRefPrefixV1 = "malt:map:radix:bucket:v1:"
	bucketRefPrefixV2 = "malt:map:radix:bucket:v2:"
	bucketCountPrefix = "malt:map:radix:bucket-count:v1:"
	bucketProofBatch  = 16
)

type bucketRefVersion uint8

const (
	bucketRefV1 bucketRefVersion = 1
	bucketRefV2 bucketRefVersion = 2
)

func bucketVersionForMALTVersion(version uint8) (bucketRefVersion, bool) {
	switch version {
	case maltcid.LegacyMALTVersionID:
		return bucketRefV1, true
	case maltcid.MALTVersionID:
		return bucketRefV2, true
	default:
		return 0, false
	}
}

func matchesRadixRootProfile(root cid.Cid, version uint8, backend maltcid.BackendKind) bool {
	return maltcid.VersionIDOf(root) == version &&
		maltcid.SemanticKindOf(root) == maltcid.SemanticKindMap &&
		maltcid.BackendKindOf(root) == backend
}

type Map struct {
	commitment   *mapping.Commitment
	materializer materializer.NodeStore
	geometry     nodegeometry.Geometry
	version      uint8
}

// ErrPathNotFound is retained as a compatibility alias for the semantic-level
// mapping absence sentinel.
var ErrPathNotFound = mapping.ErrPathNotFound

// pendingNode represents a node that needs to be persisted.
type pendingNode struct {
	root  cid.Cid
	slots []cid.Cid
}

// pendingBucket represents a bucket that needs to be persisted.
type pendingBucket struct {
	root    cid.Cid
	markers []cid.Cid
}

type leafBinding struct {
	path   arcset.Path
	value  cid.Cid
	digest [sha256.Size]byte
}

type proofEnvelope struct {
	Steps  []proofStep    `json:"steps"`
	Bucket *bucketWitness `json:"bucket,omitempty"`
}

type proofStep struct {
	Slot  []byte `json:"slot,omitempty"`
	Proof []byte `json:"proof"`
}

type bucketWitness struct {
	Entries [][]byte `json:"entries,omitempty"`
	Proof   []byte   `json:"proof"`
	Batches [][]byte `json:"batches,omitempty"`
}

func NewMap(scheme commitment.IndexCommitment, e materializer.NodeStore) (*Map, error) {
	return NewMapForVersion(scheme, e, maltcid.MALTVersionID)
}

// NewMapForVersion creates radix-map semantics that emit an exact supported
// typed-root version. Legacy mode exists only to replay and verify old complete
// views; new state should use [NewMap].
func NewMapForVersion(scheme commitment.IndexCommitment, e materializer.NodeStore, version uint8) (*Map, error) {
	if scheme == nil {
		return nil, fmt.Errorf("scheme is nil")
	}
	if e == nil {
		return nil, fmt.Errorf("materializer is nil")
	}
	geometry, err := nodegeometry.ForCapacity(scheme.MaxValues())
	if err != nil {
		return nil, fmt.Errorf("selecting radix geometry: %w", err)
	}

	commitmentHandler, err := mapping.NewCommitment(scheme)
	if err != nil {
		return nil, fmt.Errorf("failed to create map commitment: %w", err)
	}

	if version != maltcid.MALTVersionID && version != maltcid.LegacyMALTVersionID {
		return nil, fmt.Errorf("unsupported MALT version %d", version)
	}
	return &Map{commitment: commitmentHandler, materializer: e, geometry: geometry, version: version}, nil
}

// Commitment returns the underlying commitment primitives.
func (s *Map) Commitment() *mapping.Commitment {
	return s.commitment
}

func (s *Map) typedRoot(root cid.Cid) (cid.Cid, error) {
	commitmentBytes, err := maltcid.ExtractCommitment(root)
	if err != nil {
		return cid.Undef, err
	}
	return maltcid.NewTypedCIDForVersion(s.version, maltcid.SemanticKindMap, maltcid.BackendKindOf(root), commitmentBytes)
}

func (s *Map) commitSlots(slots []cid.Cid) (cid.Cid, error) {
	root, err := s.commitment.Scheme().Commit(cellsFromCIDs(slots))
	if err != nil {
		return cid.Undef, err
	}
	return s.typedRoot(root)
}

func (s *Map) bucketVersion() bucketRefVersion {
	if s.version == maltcid.LegacyMALTVersionID {
		return bucketRefV1
	}
	return bucketRefV2
}

func (s *Map) encodeBucketRef(root cid.Cid) (cid.Cid, error) {
	return encodeBucketRefVersion(root, s.bucketVersion())
}

func (s *Map) bucketCommitVector(markers []cid.Cid) []cid.Cid {
	if s.bucketVersion() == bucketRefV1 {
		return markers
	}
	return bucketVector(markers, s.commitment.Scheme().MaxValues())
}

func (s *Map) validateMutationRootVersion(root cid.Cid) error {
	if version := maltcid.VersionIDOf(root); version != s.version {
		return fmt.Errorf("map root version %d cannot be mutated by version %d semantics; replay the complete view first", version, s.version)
	}
	return nil
}

func (s *Map) Commit(ctx context.Context, namespace string, view mapping.View) (cid.Cid, error) {
	bindings, err := extractBindings(view)
	if err != nil {
		return cid.Undef, err
	}
	return s.commitRoot(ctx, namespace, bindings)
}

func (s *Map) Prove(ctx context.Context, namespace string, root cid.Cid, key arcset.Path) (mapping.Binding, structure.Proof, error) {
	if !root.Defined() {
		return mapping.Binding{}, nil, fmt.Errorf("root is undefined")
	}
	if key.IsEmpty() {
		return mapping.Binding{}, nil, fmt.Errorf("key is empty")
	}
	rootVersion := maltcid.VersionIDOf(root)
	expectedBucketVersion, ok := bucketVersionForMALTVersion(rootVersion)
	rootBackend := maltcid.BackendKindOf(root)
	if !ok || !matchesRadixRootProfile(root, rootVersion, rootBackend) {
		return mapping.Binding{}, nil, fmt.Errorf("root does not encode a supported radix map profile")
	}

	digest := hashPath(key)
	currentRoot := root
	envelope := proofEnvelope{}

	for depth := 0; depth < s.geometry.MapDepth(len(digest)); depth++ {
		finishMaterialization := observation.Start(ctx, observation.PhaseMaterialization)
		// ProveSlot below is root-bound: every supported commitment backend either
		// opens directly against currentRoot or recomputes and compares the root.
		// Loading through loadValidatedNode here would therefore perform a second
		// cryptographic opening at slot zero before opening the requested slot.
		slots, err := s.loadNodeSlots(ctx, namespace, currentRoot)
		var materializedBytes uint64
		if observation.Enabled(ctx) {
			materializedBytes = cidVectorBytes(slots)
		}
		finishMaterialization(1, uint64(len(slots)), materializedBytes)
		if err != nil {
			return mapping.Binding{}, nil, err
		}

		slotIndex, ok := s.geometry.MapDigit(digest[:], depth)
		if !ok {
			return mapping.Binding{}, nil, fmt.Errorf("invalid radix depth %d", depth)
		}
		finishOpen := observation.Start(ctx, observation.PhaseOpen)
		value, proof, err := s.commitment.ProveSlot(currentRoot, slots, slotIndex)
		finishOpen(1, 1, uint64(len(proof)))
		if err != nil {
			return mapping.Binding{}, nil, err
		}

		slotCID, err := value.AsCID()
		if err != nil {
			return mapping.Binding{}, nil, err
		}
		envelope.Steps = append(envelope.Steps, proofStep{
			Slot:  cidBytes(slotCID),
			Proof: proof,
		})

		if !slotCID.Defined() {
			finishSerialization := observation.Start(ctx, observation.PhaseSerialization)
			proofBytes, err := json.Marshal(envelope)
			finishSerialization(1, uint64(len(envelope.Steps)), uint64(len(proofBytes)))
			if err != nil {
				return mapping.Binding{}, nil, err
			}
			return mapping.Binding{Present: false}, structure.Proof(proofBytes), nil
		}

		if leafPath, leafValue, ok, err := tryDecodeLeafMarker(slotCID); err != nil {
			return mapping.Binding{}, nil, err
		} else if ok {
			if leafPath != key {
				finishSerialization := observation.Start(ctx, observation.PhaseSerialization)
				proofBytes, err := json.Marshal(envelope)
				finishSerialization(1, uint64(len(envelope.Steps)), uint64(len(proofBytes)))
				if err != nil {
					return mapping.Binding{}, nil, err
				}
				return mapping.Binding{Present: false}, structure.Proof(proofBytes), nil
			}
			finishSerialization := observation.Start(ctx, observation.PhaseSerialization)
			proofBytes, err := json.Marshal(envelope)
			finishSerialization(1, uint64(len(envelope.Steps)), uint64(len(proofBytes)))
			if err != nil {
				return mapping.Binding{}, nil, err
			}
			return mapping.Binding{Value: leafValue, Present: true}, structure.Proof(proofBytes), nil
		}

		if bucketRoot, version, ok, err := decodeBucketRef(slotCID); err != nil {
			return mapping.Binding{}, nil, err
		} else if ok {
			if version != expectedBucketVersion || !matchesRadixRootProfile(bucketRoot, rootVersion, rootBackend) {
				return mapping.Binding{}, nil, fmt.Errorf("collision bucket does not match radix root profile")
			}
			finishMaterialization := observation.Start(ctx, observation.PhaseMaterialization)
			markers, err := s.loadBucketEntries(ctx, namespace, bucketRoot)
			var materializedBytes uint64
			if observation.Enabled(ctx) {
				materializedBytes = cidVectorBytes(markers)
			}
			finishMaterialization(1, uint64(len(markers)), materializedBytes)
			if err != nil {
				return mapping.Binding{}, nil, err
			}
			index := -1
			for i, marker := range markers {
				leafPath, _, err := decodeLeafMarker(marker)
				if err != nil {
					return mapping.Binding{}, nil, err
				}
				if leafPath == key {
					index = i
					break
				}
			}
			if index < 0 {
				if version == bucketRefV1 {
					return mapping.Binding{}, nil, fmt.Errorf("legacy v1 collision bucket cannot produce a sound absence proof")
				}
				witness, err := s.proveBucketAbsence(bucketRoot, markers, key)
				if err != nil {
					return mapping.Binding{}, nil, err
				}
				envelope.Bucket = witness
				finishSerialization := observation.Start(ctx, observation.PhaseSerialization)
				proofBytes, err := json.Marshal(envelope)
				finishSerialization(1, uint64(len(envelope.Steps))+uint64(len(markers)), uint64(len(proofBytes)))
				if err != nil {
					return mapping.Binding{}, nil, err
				}
				return mapping.Binding{Present: false}, structure.Proof(proofBytes), nil
			}

			proofMarkers := markers
			if version == bucketRefV2 {
				proofMarkers = bucketVector(markers, s.commitment.Scheme().MaxValues())
			}
			finishOpen := observation.Start(ctx, observation.PhaseOpen)
			value, proof, err := s.commitment.ProveSlot(bucketRoot, proofMarkers, uint64(index))
			finishOpen(1, 1, uint64(len(proof)))
			if err != nil {
				return mapping.Binding{}, nil, err
			}
			_, leafValue, err := decodeLeafMarkerCID(value)
			if err != nil {
				return mapping.Binding{}, nil, err
			}
			envelope.Bucket = &bucketWitness{Proof: proof}
			finishSerialization := observation.Start(ctx, observation.PhaseSerialization)
			proofBytes, err := json.Marshal(envelope)
			finishSerialization(1, uint64(len(envelope.Steps))+1, uint64(len(proofBytes)))
			if err != nil {
				return mapping.Binding{}, nil, err
			}
			return mapping.Binding{Value: leafValue, Present: true}, structure.Proof(proofBytes), nil
		}

		if !matchesRadixRootProfile(slotCID, rootVersion, rootBackend) {
			return mapping.Binding{}, nil, fmt.Errorf("internal node does not match radix root profile")
		}
		currentRoot = slotCID
	}

	return mapping.Binding{}, nil, fmt.Errorf("%w: path %s", ErrPathNotFound, key.String())
}

func (s *Map) proveBucketAbsence(root cid.Cid, markers []cid.Cid, key arcset.Path) (*bucketWitness, error) {
	capacity := s.commitment.Scheme().MaxValues()
	if len(markers) < 2 || len(markers) > capacity {
		return nil, fmt.Errorf("invalid bucket size %d", len(markers))
	}
	padded := make([]cid.Cid, capacity)
	entries := make([][]byte, len(markers))
	var previous arcset.Path
	for index, marker := range markers {
		path, value, err := decodeLeafMarker(marker)
		if err != nil {
			return nil, err
		}
		canonical, err := encodeLeafMarker(path, value)
		if err != nil {
			return nil, err
		}
		if !canonical.Equals(marker) {
			return nil, fmt.Errorf("bucket entry %d is not canonically encoded", index)
		}
		if index > 0 && path <= previous {
			return nil, fmt.Errorf("bucket entries are not in canonical path order")
		}
		if path == key {
			return nil, fmt.Errorf("bucket contains queried path %s", key.String())
		}
		previous = path
		padded[index] = marker
		entries[index] = cidBytes(marker)
	}
	batches := make([][]byte, 0, (capacity+bucketProofBatch-1)/bucketProofBatch)
	for start := 0; start < capacity; start += bucketProofBatch {
		end := min(start+bucketProofBatch, capacity)
		indices := make([]uint64, end-start)
		for offset := range indices {
			indices[offset] = uint64(start + offset)
		}
		proved, proof, err := s.commitment.ProveSlots(root, padded, indices)
		if err != nil {
			return nil, err
		}
		if len(proved) != len(indices) {
			return nil, fmt.Errorf("bucket absence batch returned %d cells, want %d", len(proved), len(indices))
		}
		for offset := range proved {
			if !proved[offset].Equal(commitment.CellFromCID(padded[start+offset])) {
				return nil, fmt.Errorf("bucket absence proof cell %d mismatch", start+offset)
			}
		}
		batches = append(batches, proof)
	}
	return &bucketWitness{Entries: entries, Proof: []byte{}, Batches: batches}, nil
}

func (s *Map) verifyBucketAbsence(root cid.Cid, key arcset.Path, witness *bucketWitness) (bool, error) {
	capacity := s.commitment.Scheme().MaxValues()
	if witness == nil || len(witness.Entries) < 2 || len(witness.Entries) > capacity {
		return false, nil
	}
	padded := make([]cid.Cid, capacity)
	var previous arcset.Path
	for index, encoded := range witness.Entries {
		marker, err := cid.Cast(encoded)
		if err != nil {
			return false, err
		}
		path, value, err := decodeLeafMarker(marker)
		if err != nil {
			return false, err
		}
		canonical, err := encodeLeafMarker(path, value)
		if err != nil {
			return false, err
		}
		if !canonical.Equals(marker) {
			return false, nil
		}
		if index > 0 && path <= previous {
			return false, nil
		}
		if path == key {
			return false, nil
		}
		previous = path
		padded[index] = marker
	}
	cells := cellsFromCIDs(padded)
	batchCount := (capacity + bucketProofBatch - 1) / bucketProofBatch
	if len(witness.Batches) != batchCount || len(witness.Proof) != 0 {
		return false, nil
	}
	for batch, start := 0, 0; start < capacity; batch, start = batch+1, start+bucketProofBatch {
		end := min(start+bucketProofBatch, capacity)
		indices := make([]uint64, end-start)
		for offset := range indices {
			indices[offset] = uint64(start + offset)
		}
		ok, err := s.commitment.Scheme().BatchVerify(root, indices, cells[start:end], witness.Batches[batch])
		if err != nil || !ok {
			return ok, err
		}
	}
	return true, nil
}

func (s *Map) Verify(root cid.Cid, key arcset.Path, expected mapping.Binding, proof structure.Proof) (bool, error) {
	if !root.Defined() {
		return false, fmt.Errorf("root is undefined")
	}
	if key.IsEmpty() {
		return false, fmt.Errorf("key is empty")
	}
	if expected.Present && !expected.Value.Defined() {
		return false, fmt.Errorf("expected membership value is undefined")
	}
	if !expected.Present && expected.Value.Defined() {
		return false, fmt.Errorf("expected absence value must be undefined")
	}
	rootVersion := maltcid.VersionIDOf(root)
	expectedBucketVersion, profileOK := bucketVersionForMALTVersion(rootVersion)
	rootBackend := maltcid.BackendKindOf(root)
	if !profileOK || !matchesRadixRootProfile(root, rootVersion, rootBackend) {
		return false, fmt.Errorf("root does not encode a supported radix map profile")
	}

	var envelope proofEnvelope
	if err := json.Unmarshal(proof, &envelope); err != nil {
		return false, err
	}
	if len(envelope.Steps) == 0 {
		return false, fmt.Errorf("missing proof steps")
	}

	digest := hashPath(key)
	if len(envelope.Steps) > s.geometry.MapDepth(len(digest)) {
		return false, fmt.Errorf("proof has too many radix steps")
	}
	currentRoot := root
	var expectedLeaf cid.Cid
	var err error
	if expected.Present {
		expectedLeaf, err = encodeLeafMarker(key, expected.Value)
		if err != nil {
			return false, err
		}
	}

	for depth, step := range envelope.Steps {
		var slotCID cid.Cid
		if len(step.Slot) > 0 {
			slotCID, err = cid.Cast(step.Slot)
			if err != nil {
				return false, err
			}
		}

		slotIndex, ok := s.geometry.MapDigit(digest[:], depth)
		if !ok {
			return false, fmt.Errorf("invalid radix depth %d", depth)
		}
		ok, err = s.commitment.VerifySlot(currentRoot, slotIndex, commitment.CellFromCID(slotCID), step.Proof)
		if err != nil || !ok {
			return ok, err
		}
		if !slotCID.Defined() {
			return !expected.Present && depth == len(envelope.Steps)-1 && envelope.Bucket == nil, nil
		}

		if leafPath, leafValue, isLeaf, err := tryDecodeLeafMarker(slotCID); err != nil {
			return false, err
		} else if isLeaf {
			if depth != len(envelope.Steps)-1 || envelope.Bucket != nil {
				return false, nil
			}
			if expected.Present {
				return leafPath == key && leafValue.Equals(expected.Value), nil
			}
			return leafPath != key, nil
		}

		if bucketRoot, bucketVersion, isBucket, err := decodeBucketRef(slotCID); err != nil {
			return false, err
		} else if isBucket {
			if bucketVersion != expectedBucketVersion || !matchesRadixRootProfile(bucketRoot, rootVersion, rootBackend) {
				return false, nil
			}
			if depth != len(envelope.Steps)-1 || envelope.Bucket == nil {
				return false, nil
			}
			if !expected.Present {
				return s.verifyBucketAbsence(bucketRoot, key, envelope.Bucket)
			}
			if len(envelope.Bucket.Entries) != 0 || len(envelope.Bucket.Batches) != 0 {
				return false, nil
			}
			return s.commitment.Scheme().VerifyProof(bucketRoot, commitment.CellFromCID(expectedLeaf), envelope.Bucket.Proof)
		}

		if depth == len(envelope.Steps)-1 {
			return false, nil
		}
		if !matchesRadixRootProfile(slotCID, rootVersion, rootBackend) {
			return false, nil
		}
		currentRoot = slotCID
	}

	return false, nil
}

func (s *Map) Update(ctx context.Context, namespace string, root cid.Cid, key arcset.Path, oldValue, newValue cid.Cid) (cid.Cid, error) {
	if !root.Defined() {
		return cid.Undef, fmt.Errorf("root is undefined")
	}
	if err := s.validateMutationRootVersion(root); err != nil {
		return cid.Undef, err
	}
	if key.IsEmpty() {
		return cid.Undef, fmt.Errorf("key is empty")
	}

	newRoot, nodes, buckets, err := s.updateWithoutPersist(ctx, namespace, root, key, oldValue, newValue)
	if err != nil {
		return cid.Undef, err
	}

	// Persist all nodes
	for _, node := range nodes {
		if err := s.storeNodeSlots(ctx, namespace, node.root, node.slots); err != nil {
			return cid.Undef, err
		}
	}

	// Persist all buckets
	for _, bucket := range buckets {
		if err := s.storeBucketEntries(ctx, namespace, bucket.root, bucket.markers); err != nil {
			return cid.Undef, err
		}
	}

	return newRoot, nil
}

// updateWithoutPersist performs tree modification without persisting to ArcSet materializer.
// Returns the new root and lists of nodes/buckets that need to be persisted.
func (s *Map) updateWithoutPersist(ctx context.Context, namespace string, root cid.Cid, key arcset.Path, oldValue, newValue cid.Cid) (cid.Cid, []pendingNode, []pendingBucket, error) {
	// Use loadValidatedNode to ensure persisted node integrity
	rootSlots, err := s.loadValidatedNode(ctx, namespace, root)
	if err != nil {
		return cid.Undef, nil, nil, err
	}

	digest := hashPath(key)
	slotIndex, ok := s.geometry.MapDigit(digest[:], 0)
	if !ok {
		return cid.Undef, nil, nil, fmt.Errorf("missing root radix digit")
	}
	nextSlot, nodes, buckets, err := s.updateSubtreeWithoutPersist(ctx, namespace, rootSlots[slotIndex], digest, 1, key, oldValue, newValue)
	if err != nil {
		return cid.Undef, nil, nil, err
	}
	if cidEqual(nextSlot, rootSlots[slotIndex]) {
		return root, nil, nil, nil
	}

	nextSlots := cloneCIDs(rootSlots)
	nextSlots[slotIndex] = nextSlot
	newRoot, err := s.commitSlots(nextSlots)
	if err != nil {
		return cid.Undef, nil, nil, err
	}

	// Add this node to pending list
	nodes = append(nodes, pendingNode{root: newRoot, slots: nextSlots})
	return newRoot, nodes, buckets, nil
}

// updateWithoutPersistCached is like updateWithoutPersist but uses a node cache.
func (s *Map) updateWithoutPersistCached(ctx context.Context, namespace string, root cid.Cid, key arcset.Path, oldValue, newValue cid.Cid, nodeCache map[string][]cid.Cid) (cid.Cid, []pendingNode, []pendingBucket, error) {
	var rootSlots []cid.Cid
	if cached, ok := nodeCache[root.String()]; ok {
		// Node is from this batch - no validation needed
		rootSlots = cached
	} else {
		// Node is persisted - must validate commitment
		var err error
		rootSlots, err = s.loadValidatedNode(ctx, namespace, root)
		if err != nil {
			return cid.Undef, nil, nil, err
		}
	}

	digest := hashPath(key)
	slotIndex, ok := s.geometry.MapDigit(digest[:], 0)
	if !ok {
		return cid.Undef, nil, nil, fmt.Errorf("missing root radix digit")
	}
	nextSlot, nodes, buckets, err := s.updateSubtreeWithoutPersistCached(ctx, namespace, rootSlots[slotIndex], digest, 1, key, oldValue, newValue, nodeCache)
	if err != nil {
		return cid.Undef, nil, nil, err
	}
	if cidEqual(nextSlot, rootSlots[slotIndex]) {
		return root, nil, nil, nil
	}

	nextSlots := cloneCIDs(rootSlots)
	nextSlots[slotIndex] = nextSlot
	newRoot, err := s.commitSlots(nextSlots)
	if err != nil {
		return cid.Undef, nil, nil, err
	}

	// Add this node to pending list
	nodes = append(nodes, pendingNode{root: newRoot, slots: nextSlots})
	return newRoot, nodes, buckets, nil
}

// updateSubtreeWithoutPersistCached updates a subtree using cached nodes.
func (s *Map) updateSubtreeWithoutPersistCached(
	ctx context.Context,
	namespace string,
	current cid.Cid,
	digest [sha256.Size]byte,
	depth int,
	key arcset.Path,
	oldValue, newValue cid.Cid,
	nodeCache map[string][]cid.Cid,
) (cid.Cid, []pendingNode, []pendingBucket, error) {
	if !current.Defined() {
		if oldValue.Defined() {
			return cid.Undef, nil, nil, fmt.Errorf("path %s is absent", key.String())
		}
		if !newValue.Defined() {
			return cid.Undef, nil, nil, nil
		}
		leafCID, err := encodeLeafMarker(key, newValue)
		return leafCID, nil, nil, err
	}

	if leafPath, leafValue, ok, err := tryDecodeLeafMarker(current); err != nil {
		return cid.Undef, nil, nil, err
	} else if ok {
		switch {
		case leafPath == key:
			if !oldValue.Defined() {
				return cid.Undef, nil, nil, fmt.Errorf("path %s already exists", key.String())
			}
			if !leafValue.Equals(oldValue) {
				return cid.Undef, nil, nil, fmt.Errorf("old value mismatch at path %s", key.String())
			}
			if !newValue.Defined() {
				return cid.Undef, nil, nil, nil
			}
			leafCID, err := encodeLeafMarker(key, newValue)
			return leafCID, nil, nil, err
		default:
			if oldValue.Defined() {
				return cid.Undef, nil, nil, fmt.Errorf("path %s is absent", key.String())
			}
			if !newValue.Defined() {
				return current, nil, nil, nil
			}
			existing := newLeafBinding(leafPath, leafValue)
			inserted := leafBinding{path: key, value: newValue, digest: digest}
			return s.buildSubtreeWithoutPersist(ctx, namespace, []leafBinding{existing, inserted}, depth)
		}
	}

	if bucketRoot, version, ok, err := decodeBucketRef(current); err != nil {
		return cid.Undef, nil, nil, err
	} else if ok {
		return s.updateBucketWithoutPersist(ctx, namespace, bucketRoot, version, key, oldValue, newValue)
	}

	if depth >= s.geometry.MapDepth(len(digest)) {
		return cid.Undef, nil, nil, fmt.Errorf("unexpected radix depth overflow")
	}

	var slots []cid.Cid
	if cached, ok := nodeCache[current.String()]; ok {
		// Batch-generated node: CID is computed locally, no round-trip through ArcSet materializer
		slots = cached
	} else {
		// Persisted node: must validate commitment before trusting slot data
		var err error
		slots, err = s.loadValidatedNode(ctx, namespace, current)
		if err != nil {
			return cid.Undef, nil, nil, err
		}
	}

	slotIndex, ok := s.geometry.MapDigit(digest[:], depth)
	if !ok {
		return cid.Undef, nil, nil, fmt.Errorf("invalid radix depth %d", depth)
	}
	nextSlot, nodes, buckets, err := s.updateSubtreeWithoutPersistCached(ctx, namespace, slots[slotIndex], digest, depth+1, key, oldValue, newValue, nodeCache)
	if err != nil {
		return cid.Undef, nil, nil, err
	}
	if cidEqual(nextSlot, slots[slotIndex]) {
		return current, nil, nil, nil
	}

	nextSlots := cloneCIDs(slots)
	nextSlots[slotIndex] = nextSlot
	return s.commitOrCollapseNodeWithoutPersist(ctx, namespace, nextSlots, nodes, buckets)
}

// BatchUpdate applies multiple updates atomically and returns the final root
// only if all updates succeed. The persisted root node is opened once, updates
// are applied below their root slots, and the final root commitment is computed
// once after every subtree succeeds. If any update fails, no state is persisted
// to the ArcSet materializer.
func (s *Map) BatchUpdate(ctx context.Context, namespace string, root cid.Cid, updates []mapping.BatchUpdate) (cid.Cid, error) {
	if !root.Defined() {
		return cid.Undef, fmt.Errorf("root is undefined")
	}
	if err := s.validateMutationRootVersion(root); err != nil {
		return cid.Undef, err
	}
	if len(updates) == 0 {
		return root, nil
	}

	// Load initial root slots to seed the cache; validate commitment on the persisted root
	initialSlots, err := s.loadValidatedNode(ctx, namespace, root)
	if err != nil {
		return cid.Undef, err
	}

	// Build a cache of all materialized nodes/buckets below the root as we
	// traverse. Subsequent updates in the batch can read newly created nodes
	// without opening or persisting an intermediate root.
	nodeCache := make(map[string][]cid.Cid)
	nextRootSlots := cloneCIDs(initialSlots)

	// Accumulate all nodes and buckets that need to be persisted
	var pendingNodes []pendingNode
	var pendingBuckets []pendingBucket

	// Apply updates sequentially below their root slots without committing the
	// top-level node after each coordinate. Changes are canonical and unique at
	// the mutation boundary, while this method preserves input ordering for its
	// general public contract.
	for i, update := range updates {
		if update.Key.IsEmpty() {
			return cid.Undef, fmt.Errorf("update %d: key is empty", i)
		}
		digest := hashPath(update.Key)
		rootSlot, ok := s.geometry.MapDigit(digest[:], 0)
		if !ok {
			return cid.Undef, fmt.Errorf("update %d: missing root radix digit", i)
		}
		nextSlot, nodes, buckets, err := s.updateSubtreeWithoutPersistCached(
			ctx,
			namespace,
			nextRootSlots[rootSlot],
			digest,
			1,
			update.Key,
			update.OldValue,
			update.NewValue,
			nodeCache,
		)
		if err != nil {
			return cid.Undef, fmt.Errorf("update %d (key=%s): %w", i, update.Key.String(), err)
		}
		nextRootSlots[rootSlot] = nextSlot

		// Add new nodes to cache
		for _, node := range nodes {
			nodeCache[node.root.String()] = node.slots
		}

		pendingNodes = append(pendingNodes, nodes...)
		pendingBuckets = append(pendingBuckets, buckets...)
	}
	if slices.EqualFunc(initialSlots, nextRootSlots, cidEqual) {
		return root, nil
	}
	currentRoot, err := s.commitSlots(nextRootSlots)
	if err != nil {
		return cid.Undef, err
	}
	pendingNodes = append(pendingNodes, pendingNode{root: currentRoot, slots: nextRootSlots})

	// All updates succeeded - now persist atomically
	// First persist all nodes
	for _, node := range pendingNodes {
		if err := s.storeNodeSlots(ctx, namespace, node.root, node.slots); err != nil {
			return cid.Undef, fmt.Errorf("failed to persist node: %w", err)
		}
	}

	// Then persist all buckets
	for _, bucket := range pendingBuckets {
		if err := s.storeBucketEntries(ctx, namespace, bucket.root, bucket.markers); err != nil {
			return cid.Undef, fmt.Errorf("failed to persist bucket: %w", err)
		}
	}

	return currentRoot, nil
}

// updateSubtreeWithoutPersist updates a subtree without persisting to ArcSet materializer.
func (s *Map) updateSubtreeWithoutPersist(
	ctx context.Context,
	namespace string,
	current cid.Cid,
	digest [sha256.Size]byte,
	depth int,
	key arcset.Path,
	oldValue, newValue cid.Cid,
) (cid.Cid, []pendingNode, []pendingBucket, error) {
	if !current.Defined() {
		if oldValue.Defined() {
			return cid.Undef, nil, nil, fmt.Errorf("path %s is absent", key.String())
		}
		if !newValue.Defined() {
			return cid.Undef, nil, nil, nil
		}
		leafCID, err := encodeLeafMarker(key, newValue)
		return leafCID, nil, nil, err
	}

	if leafPath, leafValue, ok, err := tryDecodeLeafMarker(current); err != nil {
		return cid.Undef, nil, nil, err
	} else if ok {
		switch {
		case leafPath == key:
			if !oldValue.Defined() {
				return cid.Undef, nil, nil, fmt.Errorf("path %s already exists", key.String())
			}
			if !leafValue.Equals(oldValue) {
				return cid.Undef, nil, nil, fmt.Errorf("old value mismatch at path %s", key.String())
			}
			if !newValue.Defined() {
				return cid.Undef, nil, nil, nil
			}
			leafCID, err := encodeLeafMarker(key, newValue)
			return leafCID, nil, nil, err
		default:
			if oldValue.Defined() {
				return cid.Undef, nil, nil, fmt.Errorf("path %s is absent", key.String())
			}
			if !newValue.Defined() {
				return current, nil, nil, nil
			}
			existing := newLeafBinding(leafPath, leafValue)
			inserted := leafBinding{path: key, value: newValue, digest: digest}
			return s.buildSubtreeWithoutPersist(ctx, namespace, []leafBinding{existing, inserted}, depth)
		}
	}

	if bucketRoot, version, ok, err := decodeBucketRef(current); err != nil {
		return cid.Undef, nil, nil, err
	} else if ok {
		return s.updateBucketWithoutPersist(ctx, namespace, bucketRoot, version, key, oldValue, newValue)
	}

	if depth >= s.geometry.MapDepth(len(digest)) {
		return cid.Undef, nil, nil, fmt.Errorf("unexpected radix depth overflow")
	}

	slots, err := s.loadValidatedNode(ctx, namespace, current)
	if err != nil {
		return cid.Undef, nil, nil, err
	}

	slotIndex, ok := s.geometry.MapDigit(digest[:], depth)
	if !ok {
		return cid.Undef, nil, nil, fmt.Errorf("invalid radix depth %d", depth)
	}
	nextSlot, nodes, buckets, err := s.updateSubtreeWithoutPersist(ctx, namespace, slots[slotIndex], digest, depth+1, key, oldValue, newValue)
	if err != nil {
		return cid.Undef, nil, nil, err
	}
	if cidEqual(nextSlot, slots[slotIndex]) {
		return current, nil, nil, nil
	}

	nextSlots := cloneCIDs(slots)
	nextSlots[slotIndex] = nextSlot
	return s.commitOrCollapseNodeWithoutPersist(ctx, namespace, nextSlots, nodes, buckets)
}

// updateBucketWithoutPersist updates a bucket without persisting to ArcSet materializer.
func (s *Map) updateBucketWithoutPersist(ctx context.Context, namespace string, bucketRoot cid.Cid, version bucketRefVersion, key arcset.Path, oldValue, newValue cid.Cid) (cid.Cid, []pendingNode, []pendingBucket, error) {
	markers, err := s.loadBucketEntries(ctx, namespace, bucketRoot)
	if err != nil {
		return cid.Undef, nil, nil, err
	}

	index := -1
	var currentValue cid.Cid
	for i, marker := range markers {
		markerPath, markerValue, ok, err := tryDecodeLeafMarker(marker)
		if err != nil {
			return cid.Undef, nil, nil, err
		}
		if !ok {
			return cid.Undef, nil, nil, fmt.Errorf("invalid bucket marker")
		}
		if markerPath == key {
			index = i
			currentValue = markerValue
			break
		}
	}

	exists := index >= 0
	switch {
	case !oldValue.Defined() && !newValue.Defined():
		if exists {
			return cid.Undef, nil, nil, fmt.Errorf("path %s exists; absent-to-absent update is invalid", key.String())
		}
		refCID, err := encodeBucketRefVersion(bucketRoot, version)
		return refCID, nil, nil, err
	case exists:
		if !oldValue.Defined() {
			return cid.Undef, nil, nil, fmt.Errorf("path %s already exists", key.String())
		}
		if !currentValue.Equals(oldValue) {
			return cid.Undef, nil, nil, fmt.Errorf("old value mismatch at path %s", key.String())
		}
		if !newValue.Defined() {
			nextMarkers := append([]cid.Cid(nil), markers[:index]...)
			nextMarkers = append(nextMarkers, markers[index+1:]...)
			return s.commitBucketMarkersWithoutPersist(ctx, namespace, nextMarkers)
		}
		nextMarker, err := encodeLeafMarker(key, newValue)
		if err != nil {
			return cid.Undef, nil, nil, err
		}
		nextMarkers := append([]cid.Cid(nil), markers...)
		nextMarkers[index] = nextMarker
		return s.commitBucketMarkersWithoutPersist(ctx, namespace, nextMarkers)
	default:
		if oldValue.Defined() {
			return cid.Undef, nil, nil, fmt.Errorf("path %s is absent", key.String())
		}
		if !newValue.Defined() {
			refCID, err := encodeBucketRefVersion(bucketRoot, version)
			return refCID, nil, nil, err
		}
		newMarker, err := encodeLeafMarker(key, newValue)
		if err != nil {
			return cid.Undef, nil, nil, err
		}
		nextMarkers := append([]cid.Cid(nil), markers...)
		nextMarkers = append(nextMarkers, newMarker)
		return s.commitBucketMarkersWithoutPersist(ctx, namespace, nextMarkers)
	}
}

func (s *Map) updateBucket(ctx context.Context, namespace string, bucketRoot cid.Cid, key arcset.Path, oldValue, newValue cid.Cid) (cid.Cid, error) {
	markers, err := s.loadBucketEntries(ctx, namespace, bucketRoot)
	if err != nil {
		return cid.Undef, err
	}

	index := -1
	var currentValue cid.Cid
	for i, marker := range markers {
		leafPath, leafValue, err := decodeLeafMarker(marker)
		if err != nil {
			return cid.Undef, err
		}
		if leafPath == key {
			index = i
			currentValue = leafValue
			break
		}
	}

	switch {
	case index >= 0:
		if !oldValue.Defined() {
			return cid.Undef, fmt.Errorf("path %s already exists", key.String())
		}
		if !currentValue.Equals(oldValue) {
			return cid.Undef, fmt.Errorf("old value mismatch at path %s", key.String())
		}
		if !newValue.Defined() {
			next := append([]cid.Cid(nil), markers[:index]...)
			next = append(next, markers[index+1:]...)
			return s.commitBucketMarkers(ctx, namespace, next)
		}

		nextMarker, err := encodeLeafMarker(key, newValue)
		if err != nil {
			return cid.Undef, err
		}
		if len(markers) == 1 {
			return nextMarker, nil
		}
		next := cloneCIDs(markers)
		next[index] = nextMarker
		return s.commitBucketMarkers(ctx, namespace, next)

	default:
		if oldValue.Defined() {
			return cid.Undef, fmt.Errorf("path %s is absent", key.String())
		}
		if !newValue.Defined() {
			return s.encodeBucketRef(bucketRoot)
		}
		nextMarker, err := encodeLeafMarker(key, newValue)
		if err != nil {
			return cid.Undef, err
		}
		next := append([]cid.Cid(nil), markers...)
		next = append(next, nextMarker)
		slices.SortFunc(next, func(a, b cid.Cid) int {
			ap, _, err := decodeLeafMarker(a)
			if err != nil {
				return 0
			}
			bp, _, err := decodeLeafMarker(b)
			if err != nil {
				return 0
			}
			switch {
			case ap < bp:
				return -1
			case ap > bp:
				return 1
			default:
				return 0
			}
		})
		return s.commitBucketMarkers(ctx, namespace, next)
	}
}

func (s *Map) commitRoot(ctx context.Context, namespace string, bindings []leafBinding) (cid.Cid, error) {
	slots := make([]cid.Cid, s.geometry.NodeWidth())
	grouped, err := s.groupBindings(bindings, 0)
	if err != nil {
		return cid.Undef, err
	}
	for slotIndex, group := range grouped {
		child, err := s.buildSubtree(ctx, namespace, group, 1)
		if err != nil {
			return cid.Undef, err
		}
		slots[slotIndex] = child
	}
	return s.commitNode(ctx, namespace, slots)
}

// buildSubtreeWithoutPersist builds a subtree without persisting to ArcSet materializer.
func (s *Map) buildSubtreeWithoutPersist(ctx context.Context, namespace string, bindings []leafBinding, depth int) (cid.Cid, []pendingNode, []pendingBucket, error) {
	if len(bindings) == 0 {
		return cid.Undef, nil, nil, nil
	}
	if len(bindings) == 1 {
		leafCID, err := encodeLeafMarker(bindings[0].path, bindings[0].value)
		return leafCID, nil, nil, err
	}

	if depth >= s.geometry.MapDepth(sha256.Size) || allSameDigest(bindings) {
		markers := make([]cid.Cid, len(bindings))
		for i, binding := range bindings {
			marker, err := encodeLeafMarker(binding.path, binding.value)
			if err != nil {
				return cid.Undef, nil, nil, err
			}
			markers[i] = marker
		}
		return s.commitBucketMarkersWithoutPersist(ctx, namespace, markers)
	}

	slots := make([]cid.Cid, s.geometry.NodeWidth())
	var allNodes []pendingNode
	var allBuckets []pendingBucket

	grouped, err := s.groupBindings(bindings, depth)
	if err != nil {
		return cid.Undef, nil, nil, err
	}
	for slotIndex, group := range grouped {
		child, nodes, buckets, err := s.buildSubtreeWithoutPersist(ctx, namespace, group, depth+1)
		if err != nil {
			return cid.Undef, nil, nil, err
		}
		slots[slotIndex] = child
		allNodes = append(allNodes, nodes...)
		allBuckets = append(allBuckets, buckets...)
	}

	root, err := s.commitSlots(slots)
	if err != nil {
		return cid.Undef, nil, nil, err
	}

	allNodes = append(allNodes, pendingNode{root: root, slots: slots})
	return root, allNodes, allBuckets, nil
}

func (s *Map) buildSubtree(ctx context.Context, namespace string, bindings []leafBinding, depth int) (cid.Cid, error) {
	switch len(bindings) {
	case 0:
		return cid.Undef, nil
	case 1:
		return encodeLeafMarker(bindings[0].path, bindings[0].value)
	}

	if depth >= s.geometry.MapDepth(sha256.Size) || allSameDigest(bindings) {
		markers := make([]cid.Cid, len(bindings))
		for i, binding := range bindings {
			marker, err := encodeLeafMarker(binding.path, binding.value)
			if err != nil {
				return cid.Undef, err
			}
			markers[i] = marker
		}
		return s.commitBucketMarkers(ctx, namespace, markers)
	}

	slots := make([]cid.Cid, s.geometry.NodeWidth())
	grouped, err := s.groupBindings(bindings, depth)
	if err != nil {
		return cid.Undef, err
	}
	for slotIndex, group := range grouped {
		child, err := s.buildSubtree(ctx, namespace, group, depth+1)
		if err != nil {
			return cid.Undef, err
		}
		slots[slotIndex] = child
	}
	return s.commitNode(ctx, namespace, slots)
}

func (s *Map) commitNode(ctx context.Context, namespace string, slots []cid.Cid) (cid.Cid, error) {
	root, err := s.commitSlots(slots)
	if err != nil {
		return cid.Undef, err
	}
	if err := s.storeNodeSlots(ctx, namespace, root, slots); err != nil {
		return cid.Undef, err
	}
	return root, nil
}

// commitOrCollapseNodeWithoutPersist creates node commitment without persisting.
func (s *Map) commitOrCollapseNodeWithoutPersist(ctx context.Context, namespace string, slots []cid.Cid, nodes []pendingNode, buckets []pendingBucket) (cid.Cid, []pendingNode, []pendingBucket, error) {
	var only cid.Cid
	count := 0
	for _, slot := range slots {
		if !slot.Defined() {
			continue
		}
		count++
		only = slot
		if count > 1 {
			break
		}
	}
	if count == 0 {
		return cid.Undef, nodes, buckets, nil
	}
	if count == 1 {
		if _, _, ok, err := tryDecodeLeafMarker(only); err != nil {
			return cid.Undef, nil, nil, err
		} else if ok {
			return only, nodes, buckets, nil
		}
		if _, ok, err := tryDecodeBucketRef(only); err != nil {
			return cid.Undef, nil, nil, err
		} else if ok {
			return only, nodes, buckets, nil
		}
	}

	root, err := s.commitSlots(slots)
	if err != nil {
		return cid.Undef, nil, nil, err
	}

	nodes = append(nodes, pendingNode{root: root, slots: slots})
	return root, nodes, buckets, nil
}

func (s *Map) commitOrCollapseNode(ctx context.Context, namespace string, slots []cid.Cid) (cid.Cid, error) {
	var only cid.Cid
	count := 0
	for _, slot := range slots {
		if !slot.Defined() {
			continue
		}
		count++
		only = slot
		if count > 1 {
			break
		}
	}
	if count == 0 {
		return cid.Undef, nil
	}
	if count == 1 {
		if _, _, ok, err := tryDecodeLeafMarker(only); err != nil {
			return cid.Undef, err
		} else if ok {
			return only, nil
		}
		if _, ok, err := tryDecodeBucketRef(only); err != nil {
			return cid.Undef, err
		} else if ok {
			return only, nil
		}
	}
	return s.commitNode(ctx, namespace, slots)
}

// commitBucketMarkersWithoutPersist creates bucket commitment without persisting.
func (s *Map) commitBucketMarkersWithoutPersist(ctx context.Context, namespace string, markers []cid.Cid) (cid.Cid, []pendingNode, []pendingBucket, error) {
	switch len(markers) {
	case 0:
		return cid.Undef, nil, nil, nil
	case 1:
		return markers[0], nil, nil, nil
	}
	if len(markers) > s.commitment.Scheme().MaxValues() {
		return cid.Undef, nil, nil, fmt.Errorf("bucket size %d exceeds commitment capacity %d", len(markers), s.commitment.Scheme().MaxValues())
	}

	root, err := s.commitSlots(s.bucketCommitVector(markers))
	if err != nil {
		return cid.Undef, nil, nil, err
	}

	buckets := []pendingBucket{{root: root, markers: markers}}
	refCID, err := s.encodeBucketRef(root)
	if err != nil {
		return cid.Undef, nil, nil, err
	}
	return refCID, nil, buckets, nil
}

func (s *Map) commitBucketMarkers(ctx context.Context, namespace string, markers []cid.Cid) (cid.Cid, error) {
	switch len(markers) {
	case 0:
		return cid.Undef, nil
	case 1:
		return markers[0], nil
	}
	if len(markers) > s.commitment.Scheme().MaxValues() {
		return cid.Undef, fmt.Errorf("bucket size %d exceeds commitment capacity %d", len(markers), s.commitment.Scheme().MaxValues())
	}

	root, err := s.commitSlots(s.bucketCommitVector(markers))
	if err != nil {
		return cid.Undef, err
	}
	if err := s.storeBucketEntries(ctx, namespace, root, markers); err != nil {
		return cid.Undef, err
	}
	return s.encodeBucketRef(root)
}

func extractBindings(view mapping.View) ([]leafBinding, error) {
	if view == nil {
		return nil, fmt.Errorf("view is nil")
	}

	bindings := make([]leafBinding, 0, view.Len())
	iter := view.Iterate()
	for {
		path, value, ok := iter.Next()
		if !ok {
			break
		}
		bindings = append(bindings, newLeafBinding(path, value))
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}
	if !slices.IsSortedFunc(bindings, func(a, b leafBinding) int {
		switch {
		case a.path < b.path:
			return -1
		case a.path > b.path:
			return 1
		default:
			return 0
		}
	}) {
		return nil, fmt.Errorf("view iteration is not in canonical key order")
	}
	return bindings, nil
}

func (s *Map) groupBindings(bindings []leafBinding, depth int) (map[uint64][]leafBinding, error) {
	grouped := make(map[uint64][]leafBinding)
	for _, binding := range bindings {
		digit, ok := s.geometry.MapDigit(binding.digest[:], depth)
		if !ok {
			return nil, fmt.Errorf("invalid radix depth %d", depth)
		}
		grouped[digit] = append(grouped[digit], binding)
	}
	return grouped, nil
}

func allSameDigest(bindings []leafBinding) bool {
	for i := 1; i < len(bindings); i++ {
		if bindings[i].digest != bindings[0].digest {
			return false
		}
	}
	return true
}

func newLeafBinding(path arcset.Path, value cid.Cid) leafBinding {
	return leafBinding{
		path:   path,
		value:  value,
		digest: hashPath(path),
	}
}

func hashPath(path arcset.Path) [sha256.Size]byte {
	return sha256.Sum256([]byte(path.String()))
}

func (s *Map) loadValidatedNode(ctx context.Context, namespace string, root cid.Cid) ([]cid.Cid, error) {
	slots, err := s.loadNodeSlots(ctx, namespace, root)
	if err != nil {
		return nil, err
	}
	cells := cellsFromCIDs(slots)
	if rootProver, ok := s.commitment.Scheme().(commitment.IndexRootProver); ok {
		if _, _, err := rootProver.ProveAtRoot(root, cells, 0); err != nil {
			return nil, fmt.Errorf("materialized node state does not match root %s", root.String())
		}
		return slots, nil
	}
	recomputed, err := s.commitment.Scheme().Commit(cells)
	if err != nil {
		return nil, err
	}
	equal, err := maltcid.EqualCommitment(recomputed, root)
	if err != nil {
		return nil, err
	}
	if !equal {
		return nil, fmt.Errorf("materialized node state does not match root %s", root.String())
	}
	return slots, nil
}

func (s *Map) loadNodeSlots(ctx context.Context, namespace string, root cid.Cid) ([]cid.Cid, error) {
	paths := make([]arcset.Path, s.geometry.NodeWidth())
	for i := range paths {
		paths[i] = nodeSlotPath(root, uint64(i))
	}
	found, err := s.materializer.BatchGet(ctx, namespace, cid.Undef, paths)
	if err != nil {
		return nil, err
	}

	slots := make([]cid.Cid, s.geometry.NodeWidth())
	for i, path := range paths {
		if target, ok := found[path]; ok {
			slots[i] = target
		}
	}
	return slots, nil
}

func (s *Map) storeNodeSlots(ctx context.Context, namespace string, root cid.Cid, slots []cid.Cid) error {
	arcs := make(map[arcset.Path]cid.Cid)
	for i, slot := range slots {
		if !slot.Defined() {
			continue
		}
		arcs[nodeSlotPath(root, uint64(i))] = slot
	}
	if len(arcs) == 0 {
		return nil
	}
	snapshot, err := arcset.NewArcSetFromPaths(arcs)
	if err != nil {
		return err
	}
	if rooted, ok := s.materializer.(materializer.RootedNodeUpdater); ok {
		return rooted.UpdateNode(ctx, namespace, root, snapshot)
	}
	return s.materializer.Update(ctx, namespace, cid.Undef, cid.Undef, snapshot)
}

func (s *Map) loadBucketEntries(ctx context.Context, namespace string, root cid.Cid) ([]cid.Cid, error) {
	countCID, err := s.materializer.Get(ctx, namespace, cid.Undef, bucketCountPath(root))
	if err != nil {
		return nil, err
	}
	count, err := decodeBucketCountMarker(countCID)
	if err != nil {
		return nil, err
	}
	capacity := nodegeometry.KZGNodeWidth
	if s.commitment != nil && s.commitment.Scheme() != nil {
		capacity = s.commitment.Scheme().MaxValues()
	}
	if count < 2 || count > uint64(capacity) {
		return nil, fmt.Errorf("bucket count %d is outside [2,%d]", count, capacity)
	}

	paths := make([]arcset.Path, count)
	for i := uint64(0); i < count; i++ {
		paths[i] = bucketEntryPath(root, i)
	}
	found, err := s.materializer.BatchGet(ctx, namespace, cid.Undef, paths)
	if err != nil {
		return nil, err
	}

	markers := make([]cid.Cid, count)
	for i, path := range paths {
		marker, ok := found[path]
		if !ok {
			return nil, fmt.Errorf("missing bucket entry %d", i)
		}
		markers[i] = marker
	}
	return markers, nil
}

func (s *Map) storeBucketEntries(ctx context.Context, namespace string, root cid.Cid, markers []cid.Cid) error {
	arcs := make(map[arcset.Path]cid.Cid, len(markers)+1)
	countMarker, err := encodeBucketCountMarker(uint64(len(markers)))
	if err != nil {
		return err
	}
	arcs[bucketCountPath(root)] = countMarker
	for i, marker := range markers {
		arcs[bucketEntryPath(root, uint64(i))] = marker
	}
	snapshot, err := arcset.NewArcSetFromPaths(arcs)
	if err != nil {
		return err
	}
	if rooted, ok := s.materializer.(materializer.RootedNodeUpdater); ok {
		// Radix nodes link to the encoded bucket reference, not directly to the
		// bucket commitment root. Record the cache under that same reference so
		// reachability-based reclamation can follow the parent slot into the
		// bucket entries. The raw root remains part of each entry path because
		// it is also the commitment verified by bucket proofs.
		refCID, err := s.encodeBucketRef(root)
		if err != nil {
			return err
		}
		return rooted.UpdateNode(ctx, namespace, refCID, snapshot)
	}
	return s.materializer.Update(ctx, namespace, cid.Undef, cid.Undef, snapshot)
}

func cellsFromCIDs(values []cid.Cid) []commitment.Cell {
	cells := make([]commitment.Cell, len(values))
	for i, value := range values {
		cells[i] = commitment.CellFromCID(value)
	}
	return cells
}

func cloneCIDs(values []cid.Cid) []cid.Cid {
	return append([]cid.Cid(nil), values...)
}

func bucketVector(markers []cid.Cid, capacity int) []cid.Cid {
	if capacity < len(markers) {
		capacity = len(markers)
	}
	values := make([]cid.Cid, capacity)
	copy(values, markers)
	return values
}

func cidVectorBytes(values []cid.Cid) uint64 {
	var total uint64
	for _, value := range values {
		if value.Defined() {
			total += uint64(value.ByteLen())
		}
	}
	return total
}

func cidEqual(a, b cid.Cid) bool {
	if !a.Defined() && !b.Defined() {
		return true
	}
	return a.Equals(b)
}

func cidBytes(value cid.Cid) []byte {
	if !value.Defined() {
		return nil
	}
	return value.Bytes()
}

func nodeSlotPath(root cid.Cid, slot uint64) arcset.Path {
	return arcset.CanonicalizePath(fmt.Sprintf("runtime/map/radix/nodes/%s/slots/%d", root.String(), slot))
}

func bucketCountPath(root cid.Cid) arcset.Path {
	return arcset.CanonicalizePath(fmt.Sprintf("runtime/map/radix/buckets/%s/count", root.String()))
}

func bucketEntryPath(root cid.Cid, index uint64) arcset.Path {
	return arcset.CanonicalizePath(fmt.Sprintf("runtime/map/radix/buckets/%s/entries/%d", root.String(), index))
}

func encodeLeafMarker(path arcset.Path, value cid.Cid) (cid.Cid, error) {
	if path.IsEmpty() {
		return cid.Undef, fmt.Errorf("path is empty")
	}
	if !value.Defined() {
		return cid.Undef, fmt.Errorf("value is undefined")
	}

	pathBytes := []byte(path.String())
	if len(pathBytes) > 0xffff {
		return cid.Undef, fmt.Errorf("path %q is too long", path.String())
	}

	payload := make([]byte, 0, len(leafPrefix)+2+len(pathBytes)+len(value.Bytes()))
	payload = append(payload, []byte(leafPrefix)...)
	payload = binary.BigEndian.AppendUint16(payload, uint16(len(pathBytes)))
	payload = append(payload, pathBytes...)
	payload = append(payload, value.Bytes()...)

	sum, err := mh.Sum(payload, mh.IDENTITY, len(payload))
	if err != nil {
		return cid.Undef, err
	}
	return cid.NewCidV1(cid.Raw, sum), nil
}

func decodeLeafMarker(marker cid.Cid) (arcset.Path, cid.Cid, error) {
	payload, err := decodeIdentityPayload(marker)
	if err != nil {
		return "", cid.Undef, err
	}
	if len(payload) < len(leafPrefix)+2 || string(payload[:len(leafPrefix)]) != leafPrefix {
		return "", cid.Undef, fmt.Errorf("leaf marker prefix mismatch")
	}
	pathLen := int(binary.BigEndian.Uint16(payload[len(leafPrefix) : len(leafPrefix)+2]))
	offset := len(leafPrefix) + 2
	if len(payload) < offset+pathLen {
		return "", cid.Undef, fmt.Errorf("leaf marker truncated")
	}
	path := arcset.CanonicalizePath(string(payload[offset : offset+pathLen]))
	value, err := cid.Cast(payload[offset+pathLen:])
	if err != nil {
		return "", cid.Undef, err
	}
	return path, value, nil
}

func tryDecodeLeafMarker(marker cid.Cid) (arcset.Path, cid.Cid, bool, error) {
	payload, err := decodeIdentityPayload(marker)
	if err != nil {
		if !marker.Defined() {
			return "", cid.Undef, false, nil
		}
		return "", cid.Undef, false, nil
	}
	if len(payload) < len(leafPrefix) || string(payload[:len(leafPrefix)]) != leafPrefix {
		return "", cid.Undef, false, nil
	}
	path, value, err := decodeLeafMarker(marker)
	return path, value, err == nil, err
}

func decodeLeafMarkerCID(cell commitment.Cell) (arcset.Path, cid.Cid, error) {
	slotCID, err := cell.AsCID()
	if err != nil {
		return "", cid.Undef, err
	}
	return decodeLeafMarker(slotCID)
}

func encodeBucketRef(root cid.Cid) (cid.Cid, error) {
	return encodeBucketRefVersion(root, bucketRefV2)
}

func encodeBucketRefVersion(root cid.Cid, version bucketRefVersion) (cid.Cid, error) {
	if !root.Defined() {
		return cid.Undef, fmt.Errorf("bucket root is undefined")
	}
	prefix, err := bucketRefPrefix(version)
	if err != nil {
		return cid.Undef, err
	}
	payload := make([]byte, 0, len(prefix)+len(root.Bytes()))
	payload = append(payload, []byte(prefix)...)
	payload = append(payload, root.Bytes()...)
	sum, err := mh.Sum(payload, mh.IDENTITY, len(payload))
	if err != nil {
		return cid.Undef, err
	}
	return cid.NewCidV1(cid.Raw, sum), nil
}

func tryDecodeBucketRef(marker cid.Cid) (cid.Cid, bool, error) {
	root, _, ok, err := decodeBucketRef(marker)
	return root, ok, err
}

func decodeBucketRef(marker cid.Cid) (cid.Cid, bucketRefVersion, bool, error) {
	payload, err := decodeIdentityPayload(marker)
	if err != nil {
		return cid.Undef, 0, false, nil
	}
	var version bucketRefVersion
	var prefix string
	switch {
	case len(payload) >= len(bucketRefPrefixV2) && string(payload[:len(bucketRefPrefixV2)]) == bucketRefPrefixV2:
		version, prefix = bucketRefV2, bucketRefPrefixV2
	case len(payload) >= len(bucketRefPrefixV1) && string(payload[:len(bucketRefPrefixV1)]) == bucketRefPrefixV1:
		version, prefix = bucketRefV1, bucketRefPrefixV1
	default:
		return cid.Undef, 0, false, nil
	}
	root, err := cid.Cast(payload[len(prefix):])
	return root, version, err == nil, err
}

func bucketRefPrefix(version bucketRefVersion) (string, error) {
	switch version {
	case bucketRefV1:
		return bucketRefPrefixV1, nil
	case bucketRefV2:
		return bucketRefPrefixV2, nil
	default:
		return "", fmt.Errorf("unsupported collision bucket reference version %d", version)
	}
}

func encodeBucketCountMarker(count uint64) (cid.Cid, error) {
	payload := make([]byte, 0, len(bucketCountPrefix)+8)
	payload = append(payload, []byte(bucketCountPrefix)...)
	payload = binary.BigEndian.AppendUint64(payload, count)
	sum, err := mh.Sum(payload, mh.IDENTITY, len(payload))
	if err != nil {
		return cid.Undef, err
	}
	return cid.NewCidV1(cid.Raw, sum), nil
}

func decodeBucketCountMarker(marker cid.Cid) (uint64, error) {
	payload, err := decodeIdentityPayload(marker)
	if err != nil {
		return 0, err
	}
	if len(payload) != len(bucketCountPrefix)+8 || string(payload[:len(bucketCountPrefix)]) != bucketCountPrefix {
		return 0, fmt.Errorf("bucket count marker prefix mismatch")
	}
	return binary.BigEndian.Uint64(payload[len(bucketCountPrefix):]), nil
}

func decodeIdentityPayload(value cid.Cid) ([]byte, error) {
	if !value.Defined() {
		return nil, fmt.Errorf("marker is undefined")
	}
	decoded, err := mh.Decode(value.Hash())
	if err != nil {
		return nil, err
	}
	if decoded.Code != mh.IDENTITY {
		return nil, fmt.Errorf("marker is not identity-encoded")
	}
	return decoded.Digest, nil
}

var _ mapping.Semantics = (*Map)(nil)

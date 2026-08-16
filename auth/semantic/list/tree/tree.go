// Package tree implements the stable-indexed list semantic using a tree-shaped
// fixed-slot layout. Runtime operations execute against node materialization
// stored in ArcSet materializer, so proofs and updates do not require a caller-supplied view.
//
// This implementation uses the single-step commitment primitives from
// auth/semantic/list and combines them with storage access for multi-step
// tree traversal operations.
package tree

import (
	"context"
	"encoding/json"
	"fmt"

	materializer "github.com/dewebprotocol/malt-core/auth/arcset/materializer"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/semantic"
	"github.com/dewebprotocol/malt-core/auth/semantic/list"
	"github.com/dewebprotocol/malt-core/auth/semantic/list/tree/internal"
	"github.com/dewebprotocol/malt-core/auth/semantic/nodegeometry"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

type TreeList struct {
	commitment   *list.Commitment
	materializer materializer.NodeStore
	geometry     nodegeometry.Geometry
	version      uint8
}

type proofEnvelope struct {
	MetadataProof  []byte      `json:"metadata_proof"`
	MetadataTarget []byte      `json:"metadata_target,omitempty"`
	Steps          []proofStep `json:"steps,omitempty"`
}

type proofStep struct {
	Target []byte  `json:"target"`
	Proof  []byte  `json:"proof"`
	Slot   *uint64 `json:"slot,omitempty"`
}

type rangeProofEnvelope struct {
	MetadataProof []byte            `json:"metadata_proof"`
	IndexProofs   []rangeIndexProof `json:"index_proofs,omitempty"`
}

type rangeIndexProof struct {
	Index uint64 `json:"index"`
	Proof []byte `json:"proof"`
}

func NewList(scheme commitment.IndexCommitment, materializer materializer.NodeStore) (*TreeList, error) {
	return NewListForVersion(scheme, materializer, maltcid.MALTVersionID)
}

// NewListForVersion creates list semantics that emit an exact supported typed
// root version. Legacy mode is reserved for replaying complete old views.
func NewListForVersion(scheme commitment.IndexCommitment, materializer materializer.NodeStore, version uint8) (*TreeList, error) {
	geometry, err := layout.ValidateCommitment(scheme)
	if err != nil {
		return nil, err
	}
	if materializer == nil {
		return nil, fmt.Errorf("materializer is nil")
	}

	commitmentHandler, err := list.NewCommitment(scheme)
	if err != nil {
		return nil, fmt.Errorf("failed to create list commitment: %w", err)
	}

	if version != maltcid.MALTVersionID && version != maltcid.LegacyMALTVersionID {
		return nil, fmt.Errorf("unsupported MALT version %d", version)
	}
	return &TreeList{
		commitment:   commitmentHandler,
		materializer: materializer,
		geometry:     geometry,
		version:      version,
	}, nil
}

// Commitment returns the underlying commitment primitives.
func (s *TreeList) Commitment() *list.Commitment {
	return s.commitment
}

func (s *TreeList) validateMutationRootVersion(root cid.Cid) error {
	if version := maltcid.VersionIDOf(root); version != s.version {
		return fmt.Errorf("list root version %d cannot be mutated by version %d semantics; replay the complete view first", version, s.version)
	}
	return nil
}

func (s *TreeList) Commit(ctx context.Context, namespace string, view list.View) (cid.Cid, error) {
	values, err := valuesFromView(view)
	if err != nil {
		return cid.Undef, err
	}
	return s.buildPlainFromValues(ctx, namespace, values, layout.RequiredHeight(s.geometry, uint64(len(values))))
}

// CommitFixed commits fixed-width measured list chunks. The resulting root
// remains compatible with base index proofs while also supporting byte-range
// proofs over authenticated fixed chunk metadata.
func (s *TreeList) CommitFixed(ctx context.Context, namespace string, chunks []cid.Cid, chunkSize, totalSize uint64) (cid.Cid, error) {
	if chunkSize == 0 {
		return cid.Undef, fmt.Errorf("chunk size must be positive")
	}
	if uint64(len(chunks)) != chunkCount(totalSize, chunkSize) {
		return cid.Undef, fmt.Errorf("chunk count %d does not match total size %d and chunk size %d", len(chunks), totalSize, chunkSize)
	}
	for i, chunk := range chunks {
		if !chunk.Defined() {
			return cid.Undef, fmt.Errorf("chunk at index %d is undefined", i)
		}
	}
	values := append([]cid.Cid(nil), chunks...)
	return s.buildMeasuredFromValues(ctx, namespace, values, layout.RequiredHeight(s.geometry, uint64(len(values))), 0, chunkSize, totalSize)
}

func (s *TreeList) Prove(ctx context.Context, namespace string, root cid.Cid, index uint64) (list.Query, structure.Proof, error) {
	rootSlots, length, err := s.loadRoot(ctx, namespace, root)
	if err != nil {
		return list.Query{}, nil, err
	}

	query := list.Query{Length: length}
	metadataTarget, metadataProof, err := s.commitment.ProveSlot(root, rootSlots, 0)
	if err != nil {
		return list.Query{}, nil, err
	}
	envelope := proofEnvelope{MetadataProof: metadataProof}
	if target, err := metadataTarget.AsCID(); err != nil {
		return list.Query{}, nil, err
	} else if s.needsExplicitMetadataTarget(target, length) {
		envelope.MetadataTarget = metadataTarget.Bytes()
	}

	if index >= length {
		query.Key = cid.Undef
		return encodeProof(query, envelope)
	}

	height := layout.RequiredHeight(s.geometry, length)
	digits, err := layout.IndexDigits(s.geometry, index, height)
	if err != nil {
		return list.Query{}, nil, err
	}

	currentRoot := root
	currentSlots := rootSlots
	for level, digit := range digits {
		slot, err := layout.ContentSlotIndex(currentSlots, level == 0, digit)
		if err != nil {
			return list.Query{}, nil, err
		}

		target, proof, err := s.commitment.ProveSlot(currentRoot, currentSlots, slot)
		if err != nil {
			return list.Query{}, nil, err
		}
		envelope.Steps = append(envelope.Steps, newProofStep(target, proof, slot))
		if !target.Defined() {
			return list.Query{}, nil, fmt.Errorf("%w: missing child at level %d digit %d", materializer.ErrIncomplete, level, digit)
		}

		if level == len(digits)-1 {
			query.Key, err = target.AsCID()
			if err != nil {
				return list.Query{}, nil, err
			}
			return encodeProof(query, envelope)
		}
		currentRoot, err = target.AsCID()
		if err != nil {
			return list.Query{}, nil, err
		}
		currentSlots, err = s.loadNode(ctx, namespace, currentRoot, false)
		if err != nil {
			return list.Query{}, nil, err
		}
	}

	return list.Query{}, nil, fmt.Errorf("unreachable proof state")
}

func (s *TreeList) Verify(root cid.Cid, index uint64, expected list.Query, proof structure.Proof) (bool, error) {
	var envelope proofEnvelope
	if err := json.Unmarshal(proof, &envelope); err != nil {
		return false, err
	}
	if len(envelope.MetadataProof) == 0 {
		return false, fmt.Errorf("missing metadata proof")
	}

	metadataTarget, err := s.metadataTargetForVerify(expected.Length, envelope.MetadataTarget)
	if err != nil {
		return false, err
	}
	ok, err := s.commitment.VerifySlot(root, 0, metadataTarget, envelope.MetadataProof)
	if err != nil || !ok {
		return ok, err
	}

	if index >= expected.Length {
		if expected.Key.Defined() {
			return false, nil
		}
		return len(envelope.Steps) == 0, nil
	}
	if !expected.Key.Defined() {
		return false, nil
	}

	height := layout.RequiredHeight(s.geometry, expected.Length)
	if len(envelope.Steps) != height+1 {
		return false, nil
	}

	digits, err := layout.IndexDigits(s.geometry, index, height)
	if err != nil {
		return false, err
	}

	currentRoot := root
	for level, digit := range digits {
		step := envelope.Steps[level]
		target, err := parseStepTarget(step)
		if err != nil {
			return false, err
		}

		slots, err := contentSlotsForVerify(step, level == 0, digit)
		if err != nil {
			return false, err
		}
		ok, err := s.verifyAnyContentSlot(currentRoot, slots, target, step.Proof)
		if err != nil || !ok {
			return ok, err
		}

		if level == len(digits)-1 {
			return target.Equal(commitment.CellFromCID(expected.Key)), nil
		}
		currentRoot, err = target.AsCID()
		if err != nil {
			return false, err
		}
	}

	return false, nil
}

func (s *TreeList) ProveRange(ctx context.Context, namespace string, root cid.Cid, start uint64, end *uint64) (list.RangeResult, structure.Proof, error) {
	rootSlots, _, err := s.loadRoot(ctx, namespace, root)
	if err != nil {
		return list.RangeResult{}, nil, err
	}
	meta, err := fixedRangeMetadata(rootSlots[0])
	if err != nil {
		return list.RangeResult{}, nil, err
	}
	if err := validateFixedMetadata(meta); err != nil {
		return list.RangeResult{}, nil, err
	}

	_, metadataProof, err := s.commitment.ProveSlot(root, rootSlots, 0)
	if err != nil {
		return list.RangeResult{}, nil, err
	}
	result := list.RangeResult{
		Metadata: list.RangeMetadata{
			ChildCount: meta.ChildCount,
			TotalSize:  meta.TotalSize,
			ChunkSize:  meta.ChunkSize,
		},
	}
	envelope := rangeProofEnvelope{MetadataProof: metadataProof}

	endExclusive, empty, err := normalizeRange(start, end, meta.TotalSize)
	if err != nil {
		return list.RangeResult{}, nil, err
	}
	if empty {
		return encodeRangeProof(result, envelope)
	}

	first := start / meta.ChunkSize
	last := (endExclusive - 1) / meta.ChunkSize
	result.Segments = make([]cid.Cid, 0, last-first+1)
	envelope.IndexProofs = make([]rangeIndexProof, 0, last-first+1)
	for index := first; index <= last; index++ {
		query, proof, err := s.Prove(ctx, namespace, root, index)
		if err != nil {
			return list.RangeResult{}, nil, err
		}
		if !query.Key.Defined() {
			return list.RangeResult{}, nil, fmt.Errorf("missing segment at index %d", index)
		}
		result.Segments = append(result.Segments, query.Key)
		envelope.IndexProofs = append(envelope.IndexProofs, rangeIndexProof{
			Index: index,
			Proof: cloneBytes(proof),
		})
	}
	return encodeRangeProof(result, envelope)
}

func (s *TreeList) VerifyRange(root cid.Cid, start uint64, end *uint64, expected list.RangeResult, proof structure.Proof) (bool, error) {
	var envelope rangeProofEnvelope
	if err := json.Unmarshal(proof, &envelope); err != nil {
		return false, err
	}
	if len(envelope.MetadataProof) == 0 {
		return false, fmt.Errorf("missing metadata proof")
	}
	meta := layout.NodeMetadata{
		ChildCount: expected.Metadata.ChildCount,
		TotalSize:  expected.Metadata.TotalSize,
		ChunkSize:  expected.Metadata.ChunkSize,
	}
	if err := validateFixedMetadata(meta); err != nil {
		return false, err
	}
	ok, err := s.verifyMetadataSlot(root, meta, envelope.MetadataProof)
	if err != nil || !ok {
		return ok, err
	}

	endExclusive, empty, err := normalizeRange(start, end, meta.TotalSize)
	if err != nil {
		return false, err
	}
	if empty {
		return len(expected.Segments) == 0 && len(envelope.IndexProofs) == 0, nil
	}

	first := start / meta.ChunkSize
	last := (endExclusive - 1) / meta.ChunkSize
	wantCount := int(last - first + 1)
	if len(expected.Segments) != wantCount || len(envelope.IndexProofs) != wantCount {
		return false, nil
	}
	for i := 0; i < wantCount; i++ {
		index := first + uint64(i)
		indexProof := envelope.IndexProofs[i]
		if indexProof.Index != index {
			return false, nil
		}
		ok, err := s.Verify(root, index, list.Query{
			Key:    expected.Segments[i],
			Length: meta.ChildCount,
		}, structure.Proof(indexProof.Proof))
		if err != nil || !ok {
			return ok, err
		}
	}
	return true, nil
}

func (s *TreeList) Replace(ctx context.Context, namespace string, root cid.Cid, index uint64, oldKey, newKey cid.Cid) (cid.Cid, error) {
	if err := s.validateMutationRootVersion(root); err != nil {
		return cid.Undef, err
	}
	if !oldKey.Defined() {
		return cid.Undef, fmt.Errorf("old key is undefined")
	}
	if !newKey.Defined() {
		return cid.Undef, fmt.Errorf("new key is undefined")
	}
	_, length, err := s.loadRoot(ctx, namespace, root)
	if err != nil {
		return cid.Undef, err
	}
	if index >= length {
		return cid.Undef, fmt.Errorf("index %d out of range", index)
	}
	return s.replaceAt(ctx, namespace, root, true, layout.RequiredHeight(s.geometry, length), index, oldKey, newKey)
}

func (s *TreeList) Append(ctx context.Context, namespace string, root cid.Cid, key cid.Cid) (cid.Cid, uint64, error) {
	if err := s.validateMutationRootVersion(root); err != nil {
		return cid.Undef, 0, err
	}
	if !key.Defined() {
		return cid.Undef, 0, fmt.Errorf("key is undefined")
	}
	rootSlots, length, err := s.loadRoot(ctx, namespace, root)
	if err != nil {
		return cid.Undef, 0, err
	}
	if _, err := fixedRangeMetadata(rootSlots[0]); err == nil {
		return cid.Undef, 0, fmt.Errorf("append is not supported for fixed measured list roots")
	}

	newIndex := length
	newLength := length + 1
	oldHeight := layout.RequiredHeight(s.geometry, length)
	newHeight := layout.RequiredHeight(s.geometry, newLength)

	if newHeight > oldHeight {
		grownRoot, err := s.growRoot(ctx, namespace, root, oldHeight, length)
		if err != nil {
			return cid.Undef, 0, err
		}

		nextRootSlots := layout.EmptyRootSlots(s.geometry)
		rootMarker, err := plainNodeMetadata(newHeight, newLength)
		if err != nil {
			return cid.Undef, 0, err
		}
		nextRootSlots[0] = rootMarker
		content := layout.ContentSlots(nextRootSlots, true)
		content[0] = grownRoot

		childSpan, err := layout.SubtreeCapacity(s.geometry, newHeight-1)
		if err != nil {
			return cid.Undef, 0, err
		}
		rootDigit := int(newIndex / childSpan)
		localIndex := newIndex % childSpan
		childRoot, err := s.buildSparseSubtree(ctx, namespace, newHeight-1, localIndex, key)
		if err != nil {
			return cid.Undef, 0, err
		}
		content[rootDigit] = childRoot

		newRoot, err := s.commitSlots(ctx, namespace, nextRootSlots)
		return newRoot, newIndex, err
	}

	nextRootSlots := cloneSlots(rootSlots)
	rootMarker, err := plainNodeMetadata(newHeight, newLength)
	if err != nil {
		return cid.Undef, 0, err
	}
	nextRootSlots[0] = rootMarker
	content := layout.ContentSlots(nextRootSlots, true)

	if oldHeight == 0 {
		if content[newIndex].Defined() {
			return cid.Undef, 0, fmt.Errorf("append slot %d is already occupied", newIndex)
		}
		content[newIndex] = key
		newRoot, err := s.commitSlots(ctx, namespace, nextRootSlots)
		return newRoot, newIndex, err
	}

	childSpan, err := layout.SubtreeCapacity(s.geometry, oldHeight-1)
	if err != nil {
		return cid.Undef, 0, err
	}
	digit := int(newIndex / childSpan)
	localIndex := newIndex % childSpan

	if content[digit].Defined() {
		content[digit], err = s.appendInto(ctx, namespace, content[digit], oldHeight-1, localIndex, key)
	} else {
		content[digit], err = s.buildSparseSubtree(ctx, namespace, oldHeight-1, localIndex, key)
	}
	if err != nil {
		return cid.Undef, 0, err
	}

	newRoot, err := s.commitSlots(ctx, namespace, nextRootSlots)
	return newRoot, newIndex, err
}

// AppendFixed extends a fixed-width measured list by one chunk and returns the
// updated measured root. The existing measured list must end on a chunk
// boundary; extending a partial final chunk requires replacing that chunk first.
func (s *TreeList) AppendFixed(ctx context.Context, namespace string, root cid.Cid, key cid.Cid, totalSize uint64) (cid.Cid, uint64, error) {
	if err := s.validateMutationRootVersion(root); err != nil {
		return cid.Undef, 0, err
	}
	if !key.Defined() {
		return cid.Undef, 0, fmt.Errorf("key is undefined")
	}
	rootSlots, length, err := s.loadRoot(ctx, namespace, root)
	if err != nil {
		return cid.Undef, 0, err
	}
	meta, err := fixedRangeMetadata(rootSlots[0])
	if err != nil {
		return cid.Undef, 0, fmt.Errorf("root is not a fixed measured list")
	}
	if err := validateFixedMetadata(meta); err != nil {
		return cid.Undef, 0, err
	}
	if meta.ChildCount != length {
		return cid.Undef, 0, fmt.Errorf("measured child count %d does not match list length %d", meta.ChildCount, length)
	}
	if meta.TotalSize != meta.ChildCount*meta.ChunkSize {
		return cid.Undef, 0, fmt.Errorf("fixed measured append requires chunk-aligned current total size")
	}
	newLength := chunkCount(totalSize, meta.ChunkSize)
	if newLength != length+1 {
		return cid.Undef, 0, fmt.Errorf("fixed measured append child count = %d, want %d", newLength, length+1)
	}

	newIndex := length
	oldHeight := layout.RequiredHeight(s.geometry, length)
	newHeight := layout.RequiredHeight(s.geometry, newLength)

	if newHeight > oldHeight {
		nextRootSlots := layout.EmptyRootSlots(s.geometry)
		rootMarker, err := measuredNodeMetadata(newHeight, newLength, 0, meta.ChunkSize, totalSize)
		if err != nil {
			return cid.Undef, 0, err
		}
		nextRootSlots[0] = rootMarker
		content := layout.ContentSlots(nextRootSlots, true)
		content[0] = root

		childSpan, err := layout.SubtreeCapacity(s.geometry, newHeight-1)
		if err != nil {
			return cid.Undef, 0, err
		}
		rootDigit := int(newIndex / childSpan)
		localIndex := newIndex % childSpan
		childStart := uint64(rootDigit) * childSpan
		childRoot, err := s.buildMeasuredSparseSubtree(ctx, namespace, newHeight-1, localIndex, childStart, key, meta.ChunkSize, totalSize)
		if err != nil {
			return cid.Undef, 0, err
		}
		content[rootDigit] = childRoot

		newRoot, err := s.commitSlots(ctx, namespace, nextRootSlots)
		return newRoot, newIndex, err
	}

	nextRootSlots := cloneSlots(rootSlots)
	rootMarker, err := measuredNodeMetadata(newHeight, newLength, 0, meta.ChunkSize, totalSize)
	if err != nil {
		return cid.Undef, 0, err
	}
	nextRootSlots[0] = rootMarker
	content := layout.ContentSlots(nextRootSlots, true)

	if oldHeight == 0 {
		if content[newIndex].Defined() {
			return cid.Undef, 0, fmt.Errorf("append slot %d is already occupied", newIndex)
		}
		content[newIndex] = key
		newRoot, err := s.commitSlots(ctx, namespace, nextRootSlots)
		return newRoot, newIndex, err
	}

	childSpan, err := layout.SubtreeCapacity(s.geometry, oldHeight-1)
	if err != nil {
		return cid.Undef, 0, err
	}
	digit := int(newIndex / childSpan)
	localIndex := newIndex % childSpan
	childStart := uint64(digit) * childSpan
	if content[digit].Defined() {
		content[digit], err = s.appendFixedInto(ctx, namespace, content[digit], oldHeight-1, localIndex, childStart, key, meta.ChunkSize, totalSize)
	} else {
		content[digit], err = s.buildMeasuredSparseSubtree(ctx, namespace, oldHeight-1, localIndex, childStart, key, meta.ChunkSize, totalSize)
	}
	if err != nil {
		return cid.Undef, 0, err
	}

	newRoot, err := s.commitSlots(ctx, namespace, nextRootSlots)
	return newRoot, newIndex, err
}

func (s *TreeList) Truncate(ctx context.Context, namespace string, root cid.Cid, newLen uint64) (cid.Cid, error) {
	if err := s.validateMutationRootVersion(root); err != nil {
		return cid.Undef, err
	}
	rootSlots, oldLen, err := s.loadRoot(ctx, namespace, root)
	if err != nil {
		return cid.Undef, err
	}
	if _, err := fixedRangeMetadata(rootSlots[0]); err == nil && newLen != oldLen {
		return cid.Undef, fmt.Errorf("truncate is not supported for fixed measured list roots")
	}
	if newLen > oldLen {
		return cid.Undef, fmt.Errorf("new length %d exceeds current length %d", newLen, oldLen)
	}
	if newLen == oldLen {
		return root, nil
	}
	if newLen == 0 {
		return s.commitEmptyRoot(ctx, namespace)
	}

	oldHeight := layout.RequiredHeight(s.geometry, oldLen)
	newHeight := layout.RequiredHeight(s.geometry, newLen)
	return s.rebuildPrefix(ctx, namespace, root, true, oldHeight, true, newHeight, newLen)
}

func (s *TreeList) buildPlainFromValues(ctx context.Context, namespace string, values []cid.Cid, height int) (cid.Cid, error) {
	if height < 0 {
		return cid.Undef, fmt.Errorf("height must be non-negative")
	}
	marker, err := layout.EncodeNodeMetadata(layout.NodeMetadata{
		Height:     uint64(height),
		ChildCount: uint64(len(values)),
	})
	if err != nil {
		return cid.Undef, err
	}
	slots := layout.EmptyRootSlots(s.geometry)
	slots[0] = marker
	content := layout.ContentSlots(slots, true)
	if height == 0 {
		copy(content, values)
		return s.commitSlots(ctx, namespace, slots)
	}

	childSpan, err := layout.SubtreeCapacity(s.geometry, height-1)
	if err != nil {
		return cid.Undef, err
	}
	for childIdx, start := 0, 0; start < len(values); childIdx++ {
		end := start + int(childSpan)
		if end > len(values) {
			end = len(values)
		}
		childRoot, err := s.buildPlainFromValues(ctx, namespace, values[start:end], height-1)
		if err != nil {
			return cid.Undef, err
		}
		content[childIdx] = childRoot
		start = end
	}

	return s.commitSlots(ctx, namespace, slots)
}

func (s *TreeList) buildMeasuredFromValues(ctx context.Context, namespace string, values []cid.Cid, height int, startIndex, chunkSize, totalSize uint64) (cid.Cid, error) {
	if height < 0 {
		return cid.Undef, fmt.Errorf("height must be non-negative")
	}
	nodeSize, err := measuredNodeSize(startIndex, uint64(len(values)), chunkSize, totalSize)
	if err != nil {
		return cid.Undef, err
	}
	marker, err := layout.EncodeNodeMetadata(layout.NodeMetadata{
		Height:     uint64(height),
		ChildCount: uint64(len(values)),
		TotalSize:  nodeSize,
		ChunkSize:  chunkSize,
	})
	if err != nil {
		return cid.Undef, err
	}
	slots := layout.EmptyRootSlots(s.geometry)
	slots[0] = marker
	content := layout.ContentSlots(slots, true)
	if height == 0 {
		copy(content, values)
		return s.commitSlots(ctx, namespace, slots)
	}

	childSpan, err := layout.SubtreeCapacity(s.geometry, height-1)
	if err != nil {
		return cid.Undef, err
	}
	for childIdx, start := 0, 0; start < len(values); childIdx++ {
		end := start + int(childSpan)
		if end > len(values) {
			end = len(values)
		}
		childRoot, err := s.buildMeasuredFromValues(ctx, namespace, values[start:end], height-1, startIndex+uint64(start), chunkSize, totalSize)
		if err != nil {
			return cid.Undef, err
		}
		content[childIdx] = childRoot
		start = end
	}

	return s.commitSlots(ctx, namespace, slots)
}

func (s *TreeList) growRoot(ctx context.Context, namespace string, root cid.Cid, oldHeight int, oldLen uint64) (cid.Cid, error) {
	return s.rebuildPrefix(ctx, namespace, root, true, oldHeight, false, oldHeight, oldLen)
}

func (s *TreeList) rebuildPrefix(
	ctx context.Context,
	namespace string,
	root cid.Cid,
	sourceRoot bool,
	sourceHeight int,
	targetRoot bool,
	targetHeight int,
	keepLen uint64,
) (cid.Cid, error) {
	if targetHeight > sourceHeight {
		return cid.Undef, fmt.Errorf("target height %d exceeds source height %d", targetHeight, sourceHeight)
	}
	if keepLen == 0 {
		if targetRoot {
			return s.commitEmptyRoot(ctx, namespace)
		}
		return cid.Undef, nil
	}

	slots, err := s.loadNode(ctx, namespace, root, sourceRoot)
	if err != nil {
		return cid.Undef, err
	}
	content := layout.ContentSlots(slots, sourceRoot)

	if targetHeight < sourceHeight {
		if !content[0].Defined() {
			return cid.Undef, fmt.Errorf("cannot descend into empty leftmost subtree")
		}
		return s.rebuildPrefix(ctx, namespace, content[0], false, sourceHeight-1, targetRoot, targetHeight, keepLen)
	}

	var nextSlots []cid.Cid
	if targetRoot {
		nextSlots = layout.EmptyRootSlots(s.geometry)
	} else {
		nextSlots = layout.EmptyNodeSlots(s.geometry)
	}
	marker, err := plainNodeMetadata(targetHeight, keepLen)
	if err != nil {
		return cid.Undef, err
	}
	nextSlots[0] = marker
	nextContent := layout.ContentSlots(nextSlots, targetRoot)

	if targetHeight == 0 {
		if keepLen > uint64(len(content)) {
			return cid.Undef, fmt.Errorf("keep length %d exceeds leaf width %d", keepLen, len(content))
		}
		copy(nextContent, content[:int(keepLen)])
		return s.commitSlots(ctx, namespace, nextSlots)
	}

	childSpan, err := layout.SubtreeCapacity(s.geometry, targetHeight-1)
	if err != nil {
		return cid.Undef, err
	}
	fullChildren := keepLen / childSpan
	partial := keepLen % childSpan

	for i := uint64(0); i < fullChildren; i++ {
		if !content[i].Defined() {
			return cid.Undef, fmt.Errorf("missing child %d while rebuilding prefix", i)
		}
		nextContent[i] = content[i]
	}
	if partial > 0 {
		if !content[fullChildren].Defined() {
			return cid.Undef, fmt.Errorf("missing boundary child %d while rebuilding prefix", fullChildren)
		}
		nextContent[fullChildren], err = s.rebuildPrefix(
			ctx,
			namespace,
			content[fullChildren],
			false,
			targetHeight-1,
			false,
			targetHeight-1,
			partial,
		)
		if err != nil {
			return cid.Undef, err
		}
	}

	return s.commitSlots(ctx, namespace, nextSlots)
}

func (s *TreeList) replaceAt(
	ctx context.Context,
	namespace string,
	root cid.Cid,
	isRoot bool,
	height int,
	index uint64,
	oldKey cid.Cid,
	newKey cid.Cid,
) (cid.Cid, error) {
	slots, err := s.loadNode(ctx, namespace, root, isRoot)
	if err != nil {
		return cid.Undef, err
	}
	content := layout.ContentSlots(slots, isRoot)

	if height == 0 {
		if index >= uint64(len(content)) {
			return cid.Undef, fmt.Errorf("index %d out of leaf range", index)
		}
		if !content[index].Equals(oldKey) {
			return cid.Undef, fmt.Errorf("old key mismatch at index %d", index)
		}
		nextSlots := cloneSlots(slots)
		layout.ContentSlots(nextSlots, isRoot)[index] = newKey
		return s.commitSlots(ctx, namespace, nextSlots)
	}

	childSpan, err := layout.SubtreeCapacity(s.geometry, height-1)
	if err != nil {
		return cid.Undef, err
	}
	digit := int(index / childSpan)
	localIndex := index % childSpan

	if !content[digit].Defined() {
		return cid.Undef, fmt.Errorf("missing child at digit %d", digit)
	}

	newChild, err := s.replaceAt(ctx, namespace, content[digit], false, height-1, localIndex, oldKey, newKey)
	if err != nil {
		return cid.Undef, err
	}

	nextSlots := cloneSlots(slots)
	layout.ContentSlots(nextSlots, isRoot)[digit] = newChild
	return s.commitSlots(ctx, namespace, nextSlots)
}

func (s *TreeList) appendInto(ctx context.Context, namespace string, root cid.Cid, height int, index uint64, key cid.Cid) (cid.Cid, error) {
	slots, err := s.loadNode(ctx, namespace, root, false)
	if err != nil {
		return cid.Undef, err
	}

	if height == 0 {
		nextSlots := cloneSlotsForMetadataMutation(slots)
		content := layout.ContentSlots(nextSlots, false)
		if index >= uint64(len(content)) {
			return cid.Undef, fmt.Errorf("index %d out of leaf range", index)
		}
		if content[index].Defined() {
			return cid.Undef, fmt.Errorf("append slot %d is already occupied", index)
		}
		marker, err := plainNodeMetadata(height, index+1)
		if err != nil {
			return cid.Undef, err
		}
		nextSlots[0] = marker
		content[index] = key
		return s.commitSlots(ctx, namespace, nextSlots)
	}

	childSpan, err := layout.SubtreeCapacity(s.geometry, height-1)
	if err != nil {
		return cid.Undef, err
	}
	digit := int(index / childSpan)
	localIndex := index % childSpan

	nextSlots := cloneSlotsForMetadataMutation(slots)
	marker, err := plainNodeMetadata(height, index+1)
	if err != nil {
		return cid.Undef, err
	}
	nextSlots[0] = marker
	nextContent := layout.ContentSlots(nextSlots, false)
	if nextContent[digit].Defined() {
		nextContent[digit], err = s.appendInto(ctx, namespace, nextContent[digit], height-1, localIndex, key)
	} else {
		nextContent[digit], err = s.buildSparseSubtree(ctx, namespace, height-1, localIndex, key)
	}
	if err != nil {
		return cid.Undef, err
	}
	return s.commitSlots(ctx, namespace, nextSlots)
}

func (s *TreeList) buildSparseSubtree(ctx context.Context, namespace string, height int, index uint64, key cid.Cid) (cid.Cid, error) {
	if height == 0 {
		slots := layout.EmptyNodeSlots(s.geometry)
		marker, err := plainNodeMetadata(height, index+1)
		if err != nil {
			return cid.Undef, err
		}
		slots[0] = marker
		content := layout.ContentSlots(slots, false)
		if index >= uint64(len(content)) {
			return cid.Undef, fmt.Errorf("index %d out of leaf range", index)
		}
		content[index] = key
		return s.commitSlots(ctx, namespace, slots)
	}

	childSpan, err := layout.SubtreeCapacity(s.geometry, height-1)
	if err != nil {
		return cid.Undef, err
	}
	digit := int(index / childSpan)
	localIndex := index % childSpan

	slots := layout.EmptyNodeSlots(s.geometry)
	marker, err := plainNodeMetadata(height, index+1)
	if err != nil {
		return cid.Undef, err
	}
	slots[0] = marker
	content := layout.ContentSlots(slots, false)
	content[digit], err = s.buildSparseSubtree(ctx, namespace, height-1, localIndex, key)
	if err != nil {
		return cid.Undef, err
	}
	return s.commitSlots(ctx, namespace, slots)
}

func (s *TreeList) appendFixedInto(ctx context.Context, namespace string, root cid.Cid, height int, index, startIndex uint64, key cid.Cid, chunkSize, totalSize uint64) (cid.Cid, error) {
	slots, err := s.loadNode(ctx, namespace, root, false)
	if err != nil {
		return cid.Undef, err
	}

	nextSlots := cloneSlots(slots)
	marker, err := measuredNodeMetadata(height, index+1, startIndex, chunkSize, totalSize)
	if err != nil {
		return cid.Undef, err
	}
	nextSlots[0] = marker
	content := layout.ContentSlots(nextSlots, false)

	if height == 0 {
		if index >= uint64(len(content)) {
			return cid.Undef, fmt.Errorf("index %d out of leaf range", index)
		}
		if content[index].Defined() {
			return cid.Undef, fmt.Errorf("append slot %d is already occupied", index)
		}
		content[index] = key
		return s.commitSlots(ctx, namespace, nextSlots)
	}

	childSpan, err := layout.SubtreeCapacity(s.geometry, height-1)
	if err != nil {
		return cid.Undef, err
	}
	digit := int(index / childSpan)
	localIndex := index % childSpan
	childStart := startIndex + uint64(digit)*childSpan
	if content[digit].Defined() {
		content[digit], err = s.appendFixedInto(ctx, namespace, content[digit], height-1, localIndex, childStart, key, chunkSize, totalSize)
	} else {
		content[digit], err = s.buildMeasuredSparseSubtree(ctx, namespace, height-1, localIndex, childStart, key, chunkSize, totalSize)
	}
	if err != nil {
		return cid.Undef, err
	}
	return s.commitSlots(ctx, namespace, nextSlots)
}

func (s *TreeList) buildMeasuredSparseSubtree(ctx context.Context, namespace string, height int, index, startIndex uint64, key cid.Cid, chunkSize, totalSize uint64) (cid.Cid, error) {
	slots := layout.EmptyNodeSlots(s.geometry)
	marker, err := measuredNodeMetadata(height, index+1, startIndex, chunkSize, totalSize)
	if err != nil {
		return cid.Undef, err
	}
	slots[0] = marker
	content := layout.ContentSlots(slots, false)

	if height == 0 {
		if index >= uint64(len(content)) {
			return cid.Undef, fmt.Errorf("index %d out of leaf range", index)
		}
		content[index] = key
		return s.commitSlots(ctx, namespace, slots)
	}

	childSpan, err := layout.SubtreeCapacity(s.geometry, height-1)
	if err != nil {
		return cid.Undef, err
	}
	digit := int(index / childSpan)
	localIndex := index % childSpan
	childStart := startIndex + uint64(digit)*childSpan
	content[digit], err = s.buildMeasuredSparseSubtree(ctx, namespace, height-1, localIndex, childStart, key, chunkSize, totalSize)
	if err != nil {
		return cid.Undef, err
	}
	return s.commitSlots(ctx, namespace, slots)
}

func (s *TreeList) commitEmptyRoot(ctx context.Context, namespace string) (cid.Cid, error) {
	slots := layout.EmptyRootSlots(s.geometry)
	lengthMarker, err := plainNodeMetadata(0, 0)
	if err != nil {
		return cid.Undef, err
	}
	slots[0] = lengthMarker
	return s.commitSlots(ctx, namespace, slots)
}

func (s *TreeList) loadRoot(ctx context.Context, namespace string, root cid.Cid) ([]cid.Cid, uint64, error) {
	slots, err := s.loadNode(ctx, namespace, root, true)
	if err != nil {
		return nil, 0, err
	}
	meta, err := layout.DecodeNodeMetadata(slots[0])
	if err != nil {
		return nil, 0, err
	}
	return slots, meta.ChildCount, nil
}

func (s *TreeList) loadNode(ctx context.Context, namespace string, root cid.Cid, isRoot bool) ([]cid.Cid, error) {
	slots, err := layout.LoadSlots(ctx, s.materializer, namespace, root, s.geometry.NodeWidth())
	if err != nil {
		return nil, err
	}
	validateErr := s.validateSlots(root, slots)
	if validateErr == nil {
		return slots, nil
	}
	return nil, validateErr
}

// validateSlots proves one materialized cell against root when the backend
// supports root-bound openings. The compatibility fallback recomputes only for
// older third-party backends that do not expose IndexRootProver.
func (s *TreeList) validateSlots(root cid.Cid, slots []cid.Cid) error {
	cells := cellsFromCIDs(slots)
	if rootProver, ok := s.commitment.Scheme().(commitment.IndexRootProver); ok {
		if _, _, err := rootProver.ProveAtRoot(root, cells, 0); err != nil {
			return fmt.Errorf("%w: node state does not match root %s: %v", materializer.ErrIncomplete, root.String(), err)
		}
		return nil
	}
	recomputed, err := s.commitment.Scheme().Commit(cells)
	if err != nil {
		return err
	}
	ok, err := maltcid.EqualCommitment(recomputed, root)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w: node state does not match root %s", materializer.ErrIncomplete, root.String())
	}
	return nil
}

func (s *TreeList) commitSlots(ctx context.Context, namespace string, slots []cid.Cid) (cid.Cid, error) {
	root, err := s.commitment.Scheme().Commit(cellsFromCIDs(slots))
	if err != nil {
		return cid.Undef, err
	}

	// Rewrap root into the list-typed codec for the same backend.
	commBytes, err := maltcid.ExtractCommitment(root)
	if err != nil {
		return cid.Undef, err
	}
	listRoot, err := maltcid.NewTypedCIDForVersion(s.version, maltcid.SemanticKindList, maltcid.BackendKindOf(root), commBytes)
	if err != nil {
		return cid.Undef, err
	}

	if err := layout.StoreSlots(ctx, s.materializer, namespace, listRoot, slots); err != nil {
		return cid.Undef, err
	}
	return listRoot, nil
}

func (s *TreeList) verifyMetadataSlot(root cid.Cid, meta layout.NodeMetadata, proof []byte) (bool, error) {
	target, err := nodeMetadataCell(layout.NodeMetadata{
		Height:     uint64(layout.RequiredHeight(s.geometry, meta.ChildCount)),
		ChildCount: meta.ChildCount,
		TotalSize:  meta.TotalSize,
		ChunkSize:  meta.ChunkSize,
	})
	if err != nil {
		return false, err
	}
	return s.commitment.VerifySlot(root, 0, target, proof)
}

func encodeProof(query list.Query, envelope proofEnvelope) (list.Query, structure.Proof, error) {
	proofBytes, err := json.Marshal(envelope)
	if err != nil {
		return list.Query{}, nil, err
	}
	return query, structure.Proof(proofBytes), nil
}

func encodeRangeProof(result list.RangeResult, envelope rangeProofEnvelope) (list.RangeResult, structure.Proof, error) {
	proofBytes, err := json.Marshal(envelope)
	if err != nil {
		return list.RangeResult{}, nil, err
	}
	return result, structure.Proof(proofBytes), nil
}

func valuesFromView(view list.View) ([]cid.Cid, error) {
	if view == nil {
		return nil, fmt.Errorf("list view is nil")
	}

	values := make([]cid.Cid, view.Len())
	for i := uint64(0); i < view.Len(); i++ {
		value, ok := view.Get(i)
		if !ok {
			return nil, fmt.Errorf("missing value at index %d", i)
		}
		if !value.Defined() {
			return nil, fmt.Errorf("value at index %d is undefined", i)
		}
		values[i] = value
	}
	return values, nil
}

func newProofStep(target commitment.Cell, proof []byte, slot uint64) proofStep {
	provedSlot := slot
	if !target.Defined() {
		return proofStep{Proof: proof, Slot: &provedSlot}
	}
	return proofStep{
		Target: target.Bytes(),
		Proof:  proof,
		Slot:   &provedSlot,
	}
}

func parseStepTarget(step proofStep) (commitment.Cell, error) {
	if len(step.Target) == 0 {
		return nil, nil
	}
	return commitment.NewCell(step.Target), nil
}

func (s *TreeList) verifyAnyContentSlot(root cid.Cid, slots []uint64, target commitment.Cell, proof []byte) (bool, error) {
	var verifyErr error
	for _, slot := range slots {
		// Backends may mutate proof buffers while decoding; keep retries isolated.
		proofCopy := append([]byte(nil), proof...)
		ok, err := s.commitment.VerifySlot(root, slot, target, proofCopy)
		if err != nil {
			verifyErr = err
			continue
		}
		if ok {
			return true, nil
		}
	}
	if verifyErr != nil {
		return false, verifyErr
	}
	return false, nil
}

func contentSlotsForVerify(step proofStep, isRoot bool, digit int) ([]uint64, error) {
	slot := uint64(digit) + 1
	if step.Slot == nil {
		return []uint64{slot}, nil
	}
	provedSlot := *step.Slot
	if provedSlot != slot {
		return nil, fmt.Errorf("content digit %d proved slot %d, want %d", digit, provedSlot, slot)
	}
	return []uint64{provedSlot}, nil
}

func (s *TreeList) needsExplicitMetadataTarget(marker cid.Cid, length uint64) bool {
	plainMarker, err := layout.EncodeNodeMetadata(layout.NodeMetadata{
		Height:     uint64(layout.RequiredHeight(s.geometry, length)),
		ChildCount: length,
	})
	if err != nil {
		return true
	}
	return !marker.Equals(plainMarker)
}

func (s *TreeList) metadataTargetForVerify(expectedLength uint64, explicit []byte) (commitment.Cell, error) {
	if len(explicit) == 0 {
		return nodeMetadataCell(layout.NodeMetadata{
			Height:     uint64(layout.RequiredHeight(s.geometry, expectedLength)),
			ChildCount: expectedLength,
		})
	}
	cell := commitment.NewCell(explicit)
	marker, err := cell.AsCID()
	if err != nil {
		return nil, err
	}
	meta, err := layout.DecodeNodeMetadata(marker)
	if err != nil {
		return nil, err
	}
	if meta.ChildCount != expectedLength {
		return nil, fmt.Errorf("metadata target commits child count %d, expected %d", meta.ChildCount, expectedLength)
	}
	return cell, nil
}

func fixedRangeMetadata(marker cid.Cid) (layout.NodeMetadata, error) {
	meta, err := layout.DecodeNodeMetadata(marker)
	if err != nil {
		return layout.NodeMetadata{}, fmt.Errorf("root does not carry node metadata: %w", err)
	}
	if meta.ChunkSize == 0 {
		return layout.NodeMetadata{}, list.ErrNotMeasured
	}
	return meta, nil
}

func validateFixedMetadata(meta layout.NodeMetadata) error {
	if meta.ChunkSize == 0 {
		return fmt.Errorf("chunk size is zero")
	}
	if meta.ChildCount != chunkCount(meta.TotalSize, meta.ChunkSize) {
		return fmt.Errorf("child count %d does not match total size %d and chunk size %d", meta.ChildCount, meta.TotalSize, meta.ChunkSize)
	}
	return nil
}

func nodeMetadataCell(meta layout.NodeMetadata) (commitment.Cell, error) {
	marker, err := layout.EncodeNodeMetadata(meta)
	if err != nil {
		return nil, err
	}
	return commitment.CellFromCID(marker), nil
}

func plainNodeMetadata(height int, childCount uint64) (cid.Cid, error) {
	if height < 0 {
		return cid.Undef, fmt.Errorf("height must be non-negative")
	}
	return layout.EncodeNodeMetadata(layout.NodeMetadata{
		Height:     uint64(height),
		ChildCount: childCount,
	})
}

func measuredNodeMetadata(height int, childCount, startIndex, chunkSize, totalSize uint64) (cid.Cid, error) {
	if height < 0 {
		return cid.Undef, fmt.Errorf("height must be non-negative")
	}
	nodeSize, err := measuredNodeSize(startIndex, childCount, chunkSize, totalSize)
	if err != nil {
		return cid.Undef, err
	}
	return layout.EncodeNodeMetadata(layout.NodeMetadata{
		Height:     uint64(height),
		ChildCount: childCount,
		TotalSize:  nodeSize,
		ChunkSize:  chunkSize,
	})
}

func measuredNodeSize(startIndex, childCount, chunkSize, totalSize uint64) (uint64, error) {
	if chunkSize == 0 {
		return 0, fmt.Errorf("chunk size is zero")
	}
	if childCount == 0 {
		return 0, nil
	}
	if startIndex > ^uint64(0)/chunkSize {
		return 0, fmt.Errorf("measured node start index %d overflows chunk size %d", startIndex, chunkSize)
	}
	endIndex := startIndex + childCount
	if endIndex < startIndex {
		return 0, fmt.Errorf("measured node child count overflows")
	}
	if endIndex > ^uint64(0)/chunkSize {
		return 0, fmt.Errorf("measured node end index %d overflows chunk size %d", endIndex, chunkSize)
	}
	startByte := startIndex * chunkSize
	if startByte >= totalSize {
		return 0, nil
	}
	endByte := endIndex * chunkSize
	if endByte > totalSize {
		endByte = totalSize
	}
	return endByte - startByte, nil
}

func normalizeRange(start uint64, end *uint64, totalSize uint64) (endExclusive uint64, empty bool, err error) {
	endExclusive = totalSize
	if end != nil {
		endExclusive = *end
		if endExclusive > totalSize {
			endExclusive = totalSize
		}
	}
	if start > endExclusive {
		return 0, false, fmt.Errorf("range start %d exceeds end %d", start, endExclusive)
	}
	if start >= totalSize || endExclusive == start {
		return endExclusive, true, nil
	}
	return endExclusive, false, nil
}

func chunkCount(totalSize, chunkSize uint64) uint64 {
	if totalSize == 0 {
		return 0
	}
	return ((totalSize - 1) / chunkSize) + 1
}

func cloneBytes(data []byte) []byte {
	return append([]byte(nil), data...)
}

func cloneSlots(slots []cid.Cid) []cid.Cid {
	return append([]cid.Cid(nil), slots...)
}

func cloneSlotsForMetadataMutation(slots []cid.Cid) []cid.Cid {
	return cloneSlots(slots)
}

var _ list.Semantics = (*TreeList)(nil)
var _ list.MeasuredSemantics = (*TreeList)(nil)
var _ list.FixedWidthCommitter = (*TreeList)(nil)
var _ list.FixedWidthAppender = (*TreeList)(nil)
var _ list.FixedWidthSemantics = (*TreeList)(nil)

// cellsFromCIDs converts a CID slice to commitment cells.
func cellsFromCIDs(values []cid.Cid) []commitment.Cell {
	cells := make([]commitment.Cell, len(values))
	for i, value := range values {
		cells[i] = commitment.CellFromCID(value)
	}
	return cells
}

package verifier

import (
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/dewebprotocol/malt-core/auth/commitment"
	structure "github.com/dewebprotocol/malt-core/auth/semantic"
	"github.com/dewebprotocol/malt-core/auth/semantic/list"
	"github.com/dewebprotocol/malt-core/auth/semantic/nodegeometry"
	cid "github.com/ipfs/go-cid"
)

const treeNodeMetaPrefix = "malt:list:node-meta:"

// treeListVerifier is the storage-free half of the runtime tree-list
// semantic. It authenticates both index and measured-range results using only
// proof envelopes and the primitive commitment scheme.
type treeListVerifier struct {
	scheme   commitment.IndexVerifier
	geometry nodegeometry.Geometry
}

type treeProofEnvelope struct {
	MetadataProof  []byte          `json:"metadata_proof"`
	MetadataTarget []byte          `json:"metadata_target,omitempty"`
	Steps          []treeProofStep `json:"steps,omitempty"`
}

type treeProofStep struct {
	Target []byte  `json:"target"`
	Proof  []byte  `json:"proof"`
	Slot   *uint64 `json:"slot,omitempty"`
}

type treeRangeProofEnvelope struct {
	MetadataProof []byte                `json:"metadata_proof"`
	IndexProofs   []treeRangeIndexProof `json:"index_proofs,omitempty"`
}

type treeRangeIndexProof struct {
	Index uint64 `json:"index"`
	Proof []byte `json:"proof"`
}

type treeNodeMetadata struct {
	Height     uint64
	ChildCount uint64
	TotalSize  uint64
	ChunkSize  uint64
}

func newTreeListVerifier(scheme commitment.IndexVerifier, geometry nodegeometry.Geometry) ListVerifier {
	return &treeListVerifier{
		scheme:   scheme,
		geometry: geometry,
	}
}

func (v *treeListVerifier) Verify(root cid.Cid, index uint64, expected list.Query, proof structure.Proof) (bool, error) {
	if v == nil || v.scheme == nil {
		return false, fmt.Errorf("tree verifier commitment scheme is nil")
	}
	if !root.Defined() {
		return false, fmt.Errorf("root is undefined")
	}

	var envelope treeProofEnvelope
	if err := json.Unmarshal(proof, &envelope); err != nil {
		return false, err
	}
	if len(envelope.MetadataProof) == 0 {
		return false, fmt.Errorf("missing metadata proof")
	}

	metadataTarget, err := v.treeMetadataTargetForVerify(expected.Length, envelope.MetadataTarget)
	if err != nil {
		return false, err
	}
	ok, err := v.scheme.VerifyIndex(root, 0, metadataTarget, cloneProofBytes(envelope.MetadataProof))
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

	height := v.geometry.RequiredListHeight(expected.Length)
	if len(envelope.Steps) != height+1 {
		return false, nil
	}
	digits, err := v.geometry.ListIndexDigits(index, height)
	if err != nil {
		return false, err
	}

	currentRoot := root
	for level, digit := range digits {
		step := envelope.Steps[level]
		target := commitment.NewCell(step.Target)
		slot := uint64(digit) + 1
		if step.Slot != nil && *step.Slot != slot {
			return false, fmt.Errorf("content digit %d proved slot %d, want %d", digit, *step.Slot, slot)
		}
		ok, err := v.scheme.VerifyIndex(currentRoot, slot, target, cloneProofBytes(step.Proof))
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
		if !currentRoot.Defined() {
			return false, nil
		}
	}
	return false, nil
}

func (v *treeListVerifier) VerifyRange(root cid.Cid, start uint64, end *uint64, expected list.RangeResult, proof structure.Proof) (bool, error) {
	if v == nil || v.scheme == nil {
		return false, fmt.Errorf("tree verifier commitment scheme is nil")
	}
	if !root.Defined() {
		return false, fmt.Errorf("root is undefined")
	}

	var envelope treeRangeProofEnvelope
	if err := json.Unmarshal(proof, &envelope); err != nil {
		return false, err
	}
	if len(envelope.MetadataProof) == 0 {
		return false, fmt.Errorf("missing metadata proof")
	}
	meta := treeNodeMetadata{
		Height:     uint64(v.geometry.RequiredListHeight(expected.Metadata.ChildCount)),
		ChildCount: expected.Metadata.ChildCount,
		TotalSize:  expected.Metadata.TotalSize,
		ChunkSize:  expected.Metadata.ChunkSize,
	}
	if err := validateTreeFixedMetadata(meta); err != nil {
		return false, err
	}
	metadataTarget, err := treeNodeMetadataCell(meta)
	if err != nil {
		return false, err
	}
	ok, err := v.scheme.VerifyIndex(root, 0, metadataTarget, cloneProofBytes(envelope.MetadataProof))
	if err != nil || !ok {
		return ok, err
	}

	endExclusive, empty, err := normalizeTreeRange(start, end, meta.TotalSize)
	if err != nil {
		return false, err
	}
	if empty {
		return len(expected.Segments) == 0 && len(envelope.IndexProofs) == 0, nil
	}
	first := start / meta.ChunkSize
	last := (endExclusive - 1) / meta.ChunkSize
	wantCount64 := last - first + 1
	if wantCount64 > uint64(maxInt()) {
		return false, fmt.Errorf("range proof segment count %d overflows int", wantCount64)
	}
	wantCount := int(wantCount64)
	if len(expected.Segments) != wantCount || len(envelope.IndexProofs) != wantCount {
		return false, nil
	}
	for i := 0; i < wantCount; i++ {
		index := first + uint64(i)
		indexProof := envelope.IndexProofs[i]
		if indexProof.Index != index || !expected.Segments[i].Defined() {
			return false, nil
		}
		ok, err := v.Verify(root, index, list.Query{
			Key:    expected.Segments[i],
			Length: meta.ChildCount,
		}, structure.Proof(indexProof.Proof))
		if err != nil || !ok {
			return ok, err
		}
	}
	return true, nil
}

func (v *treeListVerifier) treeMetadataTargetForVerify(expectedLength uint64, explicit []byte) (commitment.Cell, error) {
	if len(explicit) == 0 {
		return treeNodeMetadataCell(treeNodeMetadata{
			Height:     uint64(v.geometry.RequiredListHeight(expectedLength)),
			ChildCount: expectedLength,
		})
	}
	cell := commitment.NewCell(explicit)
	marker, err := cell.AsCID()
	if err != nil {
		return nil, err
	}
	meta, err := decodeTreeNodeMetadata(marker)
	if err != nil {
		return nil, err
	}
	if meta.ChildCount != expectedLength {
		return nil, fmt.Errorf("metadata target commits child count %d, expected %d", meta.ChildCount, expectedLength)
	}
	return cell, nil
}

func treeNodeMetadataCell(meta treeNodeMetadata) (commitment.Cell, error) {
	marker, err := encodeTreeNodeMetadata(meta)
	if err != nil {
		return nil, err
	}
	return commitment.CellFromCID(marker), nil
}

func encodeTreeNodeMetadata(meta treeNodeMetadata) (cid.Cid, error) {
	if meta.ChunkSize == 0 && meta.TotalSize != 0 {
		return cid.Undef, fmt.Errorf("plain node metadata cannot carry total size %d", meta.TotalSize)
	}
	if meta.ChunkSize > 0 && meta.ChildCount == 0 && meta.TotalSize != 0 {
		return cid.Undef, fmt.Errorf("measured empty node cannot carry total size %d", meta.TotalSize)
	}
	payload := make([]byte, len(treeNodeMetaPrefix)+32)
	copy(payload, treeNodeMetaPrefix)
	binary.BigEndian.PutUint64(payload[len(treeNodeMetaPrefix):], meta.Height)
	binary.BigEndian.PutUint64(payload[len(treeNodeMetaPrefix)+8:], meta.ChildCount)
	binary.BigEndian.PutUint64(payload[len(treeNodeMetaPrefix)+16:], meta.TotalSize)
	binary.BigEndian.PutUint64(payload[len(treeNodeMetaPrefix)+24:], meta.ChunkSize)
	return identityCID(payload)
}

func decodeTreeNodeMetadata(marker cid.Cid) (treeNodeMetadata, error) {
	payload, err := decodeIdentityPayload(marker)
	if err != nil {
		return treeNodeMetadata{}, err
	}
	if len(payload) != len(treeNodeMetaPrefix)+32 {
		return treeNodeMetadata{}, fmt.Errorf("node metadata marker payload has unexpected size %d", len(payload))
	}
	if string(payload[:len(treeNodeMetaPrefix)]) != treeNodeMetaPrefix {
		return treeNodeMetadata{}, fmt.Errorf("node metadata marker prefix mismatch")
	}
	meta := treeNodeMetadata{
		Height:     binary.BigEndian.Uint64(payload[len(treeNodeMetaPrefix):]),
		ChildCount: binary.BigEndian.Uint64(payload[len(treeNodeMetaPrefix)+8:]),
		TotalSize:  binary.BigEndian.Uint64(payload[len(treeNodeMetaPrefix)+16:]),
		ChunkSize:  binary.BigEndian.Uint64(payload[len(treeNodeMetaPrefix)+24:]),
	}
	if meta.ChunkSize == 0 && meta.TotalSize != 0 {
		return treeNodeMetadata{}, fmt.Errorf("plain node metadata carries total size %d", meta.TotalSize)
	}
	if meta.ChunkSize > 0 && meta.ChildCount == 0 && meta.TotalSize != 0 {
		return treeNodeMetadata{}, fmt.Errorf("measured empty node carries total size %d", meta.TotalSize)
	}
	return meta, nil
}

func validateTreeFixedMetadata(meta treeNodeMetadata) error {
	if meta.ChunkSize == 0 {
		return fmt.Errorf("chunk size is zero")
	}
	if meta.ChildCount != treeChunkCount(meta.TotalSize, meta.ChunkSize) {
		return fmt.Errorf("child count %d does not match total size %d and chunk size %d", meta.ChildCount, meta.TotalSize, meta.ChunkSize)
	}
	return nil
}

func normalizeTreeRange(start uint64, end *uint64, totalSize uint64) (uint64, bool, error) {
	endExclusive := totalSize
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

func treeChunkCount(totalSize, chunkSize uint64) uint64 {
	if totalSize == 0 {
		return 0
	}
	return ((totalSize - 1) / chunkSize) + 1
}

func maxInt() int {
	return int(^uint(0) >> 1)
}

var _ MeasuredListVerifier = (*treeListVerifier)(nil)

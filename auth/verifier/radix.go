package verifier

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	structure "github.com/dewebprotocol/malt-core/auth/semantic"
	"github.com/dewebprotocol/malt-core/auth/semantic/mapping"
	"github.com/dewebprotocol/malt-core/auth/semantic/nodegeometry"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

const (
	radixLeafPrefix     = "malt:map:radix:leaf:v1:"
	radixBucketPrefixV1 = "malt:map:radix:bucket:v1:"
	radixBucketPrefixV2 = "malt:map:radix:bucket:v2:"
	radixBucketBatch    = 16
)

// radixMapVerifier is the storage-free half of the runtime radix-map
// semantic. Its proof envelope and marker encodings intentionally mirror the
// locked runtime wire format, but verification requires only the primitive
// commitment scheme.
type radixMapVerifier struct {
	scheme   commitment.IndexVerifier
	geometry nodegeometry.Geometry
}

type radixProofEnvelope struct {
	Steps  []radixProofStep    `json:"steps"`
	Bucket *radixBucketWitness `json:"bucket,omitempty"`
}

type radixProofStep struct {
	Slot  []byte `json:"slot,omitempty"`
	Proof []byte `json:"proof"`
}

type radixBucketWitness struct {
	Entries [][]byte `json:"entries,omitempty"`
	Proof   []byte   `json:"proof"`
	Batches [][]byte `json:"batches,omitempty"`
}

func (v *radixMapVerifier) verifyBucketAbsence(root cid.Cid, key arcset.Path, witness *radixBucketWitness) (bool, error) {
	capacity := v.scheme.MaxValues()
	if witness == nil || len(witness.Entries) < 2 || len(witness.Entries) > capacity {
		return false, nil
	}
	values := make([]commitment.Cell, capacity)
	var previous arcset.Path
	for index, encoded := range witness.Entries {
		marker, err := cid.Cast(encoded)
		if err != nil {
			return false, err
		}
		path, value, err := decodeRadixLeafMarker(marker)
		if err != nil {
			return false, err
		}
		canonical, err := encodeRadixLeafMarker(path, value)
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
		values[index] = commitment.CellFromCID(marker)
	}
	batchCount := (capacity + radixBucketBatch - 1) / radixBucketBatch
	if len(witness.Batches) != batchCount || len(witness.Proof) != 0 {
		return false, nil
	}
	for batch, start := 0, 0; start < capacity; batch, start = batch+1, start+radixBucketBatch {
		end := min(start+radixBucketBatch, capacity)
		indices := make([]uint64, end-start)
		for offset := range indices {
			indices[offset] = uint64(start + offset)
		}
		ok, err := v.scheme.BatchVerify(root, indices, values[start:end], cloneProofBytes(witness.Batches[batch]))
		if err != nil || !ok {
			return ok, err
		}
	}
	return true, nil
}

func newRadixMapVerifier(scheme commitment.IndexVerifier, geometry nodegeometry.Geometry) MapVerifier {
	return &radixMapVerifier{scheme: scheme, geometry: geometry}
}

func (v *radixMapVerifier) Verify(root cid.Cid, key arcset.Path, expected mapping.Binding, proof structure.Proof) (bool, error) {
	if v == nil || v.scheme == nil {
		return false, fmt.Errorf("radix verifier commitment scheme is nil")
	}
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
	var expectedBucketVersion uint8
	switch rootVersion {
	case maltcid.LegacyMALTVersionID:
		expectedBucketVersion = 1
	case maltcid.MALTVersionID:
		expectedBucketVersion = 2
	default:
		return false, fmt.Errorf("root does not encode a supported radix map version")
	}
	rootBackend := maltcid.BackendKindOf(root)
	matchesRootProfile := func(candidate cid.Cid) bool {
		return maltcid.VersionIDOf(candidate) == rootVersion &&
			maltcid.SemanticKindOf(candidate) == maltcid.SemanticKindMap &&
			maltcid.BackendKindOf(candidate) == rootBackend
	}
	if !matchesRootProfile(root) {
		return false, fmt.Errorf("root does not encode a supported radix map profile")
	}

	var envelope radixProofEnvelope
	if err := json.Unmarshal(proof, &envelope); err != nil {
		return false, err
	}
	if len(envelope.Steps) == 0 {
		return false, fmt.Errorf("missing proof steps")
	}

	digest := sha256.Sum256([]byte(key.String()))
	if len(envelope.Steps) > v.geometry.MapDepth(len(digest)) {
		return false, fmt.Errorf("proof has too many radix steps")
	}
	currentRoot := root
	var expectedLeaf cid.Cid
	var err error
	if expected.Present {
		expectedLeaf, err = encodeRadixLeafMarker(key, expected.Value)
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

		slotIndex, ok := v.geometry.MapDigit(digest[:], depth)
		if !ok {
			return false, fmt.Errorf("invalid radix depth %d", depth)
		}
		ok, err = v.scheme.VerifyIndex(currentRoot, slotIndex, commitment.CellFromCID(slotCID), cloneProofBytes(step.Proof))
		if err != nil || !ok {
			return ok, err
		}
		if !slotCID.Defined() {
			return !expected.Present && depth == len(envelope.Steps)-1 && envelope.Bucket == nil, nil
		}

		if leafPath, leafValue, isLeaf, err := tryDecodeRadixLeafMarker(slotCID); err != nil {
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

		if bucketRoot, bucketVersion, isBucket, err := decodeRadixBucketRef(slotCID); err != nil {
			return false, err
		} else if isBucket {
			if bucketVersion != expectedBucketVersion || !matchesRootProfile(bucketRoot) {
				return false, nil
			}
			if depth != len(envelope.Steps)-1 || envelope.Bucket == nil {
				return false, nil
			}
			if !expected.Present {
				if bucketVersion == 1 {
					return false, nil
				}
				return v.verifyBucketAbsence(bucketRoot, key, envelope.Bucket)
			}
			if len(envelope.Bucket.Entries) != 0 || len(envelope.Bucket.Batches) != 0 {
				return false, nil
			}
			return v.scheme.VerifyProof(bucketRoot, commitment.CellFromCID(expectedLeaf), cloneProofBytes(envelope.Bucket.Proof))
		}

		if depth == len(envelope.Steps)-1 {
			return false, nil
		}
		if !matchesRootProfile(slotCID) {
			return false, nil
		}
		currentRoot = slotCID
	}

	return false, nil
}

func encodeRadixLeafMarker(path arcset.Path, value cid.Cid) (cid.Cid, error) {
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
	payload := make([]byte, 0, len(radixLeafPrefix)+2+len(pathBytes)+len(value.Bytes()))
	payload = append(payload, []byte(radixLeafPrefix)...)
	payload = binary.BigEndian.AppendUint16(payload, uint16(len(pathBytes)))
	payload = append(payload, pathBytes...)
	payload = append(payload, value.Bytes()...)
	return identityCID(payload)
}

func decodeRadixLeafMarker(marker cid.Cid) (arcset.Path, cid.Cid, error) {
	payload, err := decodeIdentityPayload(marker)
	if err != nil {
		return "", cid.Undef, err
	}
	if len(payload) < len(radixLeafPrefix)+2 || string(payload[:len(radixLeafPrefix)]) != radixLeafPrefix {
		return "", cid.Undef, fmt.Errorf("leaf marker prefix mismatch")
	}
	pathLen := int(binary.BigEndian.Uint16(payload[len(radixLeafPrefix) : len(radixLeafPrefix)+2]))
	offset := len(radixLeafPrefix) + 2
	if len(payload) < offset+pathLen {
		return "", cid.Undef, fmt.Errorf("leaf marker truncated")
	}
	path := arcset.CanonicalizePath(string(payload[offset : offset+pathLen]))
	if path.IsEmpty() {
		return "", cid.Undef, fmt.Errorf("leaf marker path is empty")
	}
	value, err := cid.Cast(payload[offset+pathLen:])
	if err != nil {
		return "", cid.Undef, err
	}
	return path, value, nil
}

func tryDecodeRadixLeafMarker(marker cid.Cid) (arcset.Path, cid.Cid, bool, error) {
	payload, err := decodeIdentityPayload(marker)
	if err != nil {
		return "", cid.Undef, false, nil
	}
	if len(payload) < len(radixLeafPrefix) || string(payload[:len(radixLeafPrefix)]) != radixLeafPrefix {
		return "", cid.Undef, false, nil
	}
	path, value, err := decodeRadixLeafMarker(marker)
	return path, value, err == nil, err
}

func decodeRadixBucketRef(marker cid.Cid) (cid.Cid, uint8, bool, error) {
	payload, err := decodeIdentityPayload(marker)
	if err != nil {
		return cid.Undef, 0, false, nil
	}
	var version uint8
	var prefix string
	switch {
	case len(payload) >= len(radixBucketPrefixV2) && string(payload[:len(radixBucketPrefixV2)]) == radixBucketPrefixV2:
		version, prefix = 2, radixBucketPrefixV2
	case len(payload) >= len(radixBucketPrefixV1) && string(payload[:len(radixBucketPrefixV1)]) == radixBucketPrefixV1:
		version, prefix = 1, radixBucketPrefixV1
	default:
		return cid.Undef, 0, false, nil
	}
	root, err := cid.Cast(payload[len(prefix):])
	return root, version, err == nil, err
}

func identityCID(payload []byte) (cid.Cid, error) {
	sum, err := mh.Sum(payload, mh.IDENTITY, len(payload))
	if err != nil {
		return cid.Undef, err
	}
	return cid.NewCidV1(cid.Raw, sum), nil
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

func cloneProofBytes(proof []byte) []byte {
	return append([]byte(nil), proof...)
}

var _ MapVerifier = (*radixMapVerifier)(nil)

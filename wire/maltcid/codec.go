// Package maltcid defines MALT-specific multicodec constants and CID utilities.
// MALT typed roots use the 0x300000-0x30FFFF slice of the multicodec Private
// Use Area. The low 16 bits form the locked 0x30VSBB layout:
//
//	V  = 4-bit MALT wire-format version
//	S  = 4-bit semantic kind
//	BB = 8-bit commitment backend suite
//
// A codec is constructed as:
//
//	0x300000 | (version << 12) | (semantic << 8) | backend
//
// Current allocations:
//
//	malt-map-kzg  = 0x303101
//	malt-list-kzg = 0x303201
//	malt-map-ipa  = 0x303102
//	malt-list-ipa = 0x303202
//
// This file preserves historical V=2/V=3 roots exactly. Current SDK builders
// emit V=0 self-describing Roots defined in root.go (0x30VLAA +
// multicommitment). Historical constants are not the current Root version.
package maltcid

import (
	"bytes"
	"fmt"

	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

// MALTVersionID is the frozen historical V=3 typed-root identifier.
// Deprecated: use RootVersion for current Roots. Kept for exact old replay.
const MALTVersionID uint8 = 3

// LegacyMALTVersionID identifies version-2 roots retained for decode, proof,
// and exact complete-view replay compatibility. Default constructors never emit
// this version.
const LegacyMALTVersionID uint8 = 2

const (
	codecMaltRootBase = 0x300000
	codecMaltRootMax  = 0x30FFFF

	codecVersionShift  = 12
	codecSemanticShift = 8

	semanticIDMap  = 0x1
	semanticIDList = 0x2

	backendIDKZG = 0x01
	backendIDIPA = 0x02
)

// Typed MALT multicodecs in the 0x30VSBB layout.
const (
	CodecMaltMapKZG = codecMaltRootBase |
		uint64(MALTVersionID)<<codecVersionShift |
		semanticIDMap<<codecSemanticShift |
		backendIDKZG
	CodecMaltListKZG = codecMaltRootBase |
		uint64(MALTVersionID)<<codecVersionShift |
		semanticIDList<<codecSemanticShift |
		backendIDKZG
	CodecMaltMapIPA = codecMaltRootBase |
		uint64(MALTVersionID)<<codecVersionShift |
		semanticIDMap<<codecSemanticShift |
		backendIDIPA
	CodecMaltListIPA = codecMaltRootBase |
		uint64(MALTVersionID)<<codecVersionShift |
		semanticIDList<<codecSemanticShift |
		backendIDIPA
)

// SemanticKind indicates the structural semantic encoded in the typed CID.
type SemanticKind string

const (
	SemanticKindUnknown SemanticKind = "unknown"
	SemanticKindMap     SemanticKind = "map"
	SemanticKindList    SemanticKind = "list"
)

// BackendKind indicates the primitive commitment backend used by the typed CID.
type BackendKind string

const (
	BackendKindUnknown BackendKind = "unknown"
	BackendKindKZG     BackendKind = "kzg"
	BackendKindIPA     BackendKind = "ipa"
)

// CodecMaltKZG is an alias for [CodecMaltMapKZG] (map roots use KZG in the current prototype).
// Deprecated: prefer CodecMaltMapKZG for new code.
const CodecMaltKZG = CodecMaltMapKZG

// CodecMaltIPA is an alias for [CodecMaltMapIPA].
// Deprecated: prefer CodecMaltMapIPA for new code.
const CodecMaltIPA = CodecMaltMapIPA

// Commitment size constants
const (
	KZGCommitmentSize = 48 // KZGCommitmentSize is the size of a KZG commitment in bytes (48 bytes).
	IPACommitmentSize = 32 // IPACommitmentSize is the size of an IPA commitment in bytes (32 bytes).
)

type backendDescriptor struct {
	id             uint8
	kind           BackendKind
	displayName    string
	commitmentSize int
}

var backendRegistry = [...]backendDescriptor{
	{id: backendIDKZG, kind: BackendKindKZG, displayName: "KZG", commitmentSize: KZGCommitmentSize},
	{id: backendIDIPA, kind: BackendKindIPA, displayName: "IPA", commitmentSize: IPACommitmentSize},
}

// NewKZGCid creates a CID from KZG commitment bytes using the malt-map-kzg codec.
func NewKZGCid(commitment []byte) (cid.Cid, error) {
	return NewTypedCID(SemanticKindMap, BackendKindKZG, commitment)
}

// NewMapKZGCid is an alias for [NewKZGCid].
func NewMapKZGCid(commitment []byte) (cid.Cid, error) {
	return NewKZGCid(commitment)
}

// NewListKZGCid creates a CID from KZG commitment bytes using the malt-list-kzg codec.
func NewListKZGCid(commitment []byte) (cid.Cid, error) {
	return NewTypedCID(SemanticKindList, BackendKindKZG, commitment)
}

// NewIPACid creates a CID from IPA commitment bytes using the malt-map-ipa codec.
func NewIPACid(commitment []byte) (cid.Cid, error) {
	return NewTypedCID(SemanticKindMap, BackendKindIPA, commitment)
}

// NewMapIPACid is an alias for [NewIPACid].
func NewMapIPACid(commitment []byte) (cid.Cid, error) {
	return NewIPACid(commitment)
}

// NewListIPACid creates a CID from IPA commitment bytes using the malt-list-ipa codec.
func NewListIPACid(commitment []byte) (cid.Cid, error) {
	return NewTypedCID(SemanticKindList, BackendKindIPA, commitment)
}

// NewTypedCID constructs a typed MALT CID for the given semantic/backend kinds.
func NewTypedCID(semantic SemanticKind, backend BackendKind, commitment []byte) (cid.Cid, error) {
	return NewTypedCIDForVersion(MALTVersionID, semantic, backend, commitment)
}

// NewTypedCIDForVersion constructs a typed MALT CID for a supported wire
// version. It is intended for exact replay of decode-compatible legacy roots;
// new application state should use [NewTypedCID].
func NewTypedCIDForVersion(versionID uint8, semantic SemanticKind, backend BackendKind, commitment []byte) (cid.Cid, error) {
	codec, descriptor, err := codecForVersion(versionID, semantic, backend)
	if err != nil {
		return cid.Undef, err
	}
	if len(commitment) != descriptor.commitmentSize {
		return cid.Undef, fmt.Errorf(
			"invalid %s commitment size: %d, expected %d",
			descriptor.displayName, len(commitment), descriptor.commitmentSize,
		)
	}
	return newMaltCid(codec, commitment)
}

// newMaltCid creates a CIDv1 with the given codec and commitment bytes.
// Uses identity multihash (0x00) to store the commitment directly.
func newMaltCid(codec uint64, commitment []byte) (cid.Cid, error) {
	mhash, err := mh.Encode(commitment, mh.IDENTITY)
	if err != nil {
		return cid.Cid{}, fmt.Errorf("failed to create identity multihash: %w", err)
	}
	return cid.NewCidV1(codec, mhash), nil
}

// IsMaltCid checks if a CID carries a supported MALT version, semantic kind,
// backend suite, and combination in the 0x30VSBB root-codec layout, using an
// identity multihash whose digest has the size required by that backend.
func IsMaltCid(c cid.Cid) bool {
	_, _, err := decodeRoot(c)
	return err == nil
}

// VersionIDOf returns the encoded MALT wire-format version for a codec in the
// typed-root subrange. It returns zero for values outside that subrange. A
// nonzero result does not by itself mean the version is supported; use
// [IsMaltCid] for complete classification.
func VersionIDOf(c cid.Cid) uint8 {
	codec := c.Prefix().Codec
	if codec < codecMaltRootBase || codec > codecMaltRootMax {
		return 0
	}
	return uint8((codec - codecMaltRootBase) >> codecVersionShift)
}

// SemanticKindOf returns the semantic kind for a typed MALT CID.
func SemanticKindOf(c cid.Cid) SemanticKind {
	parts, _, err := decodeRoot(c)
	if err != nil {
		return SemanticKindUnknown
	}
	return parts.semantic
}

// BackendKindOf returns the backend kind for a typed MALT CID.
func BackendKindOf(c cid.Cid) BackendKind {
	parts, _, err := decodeRoot(c)
	if err != nil {
		return BackendKindUnknown
	}
	return parts.backend.kind
}

// GetMaltCodec returns the MALT codec value for a CID.
// Returns 0 if the CID is not a MALT structure root.
func GetMaltCodec(c cid.Cid) uint64 {
	if IsMaltCid(c) {
		return c.Prefix().Codec
	}
	return 0
}

// ExtractCommitment extracts the raw commitment bytes from a MALT structure CID.
func ExtractCommitment(c cid.Cid) ([]byte, error) {
	_, digest, err := decodeRoot(c)
	return digest, err
}

func decodeRoot(c cid.Cid) (codecParts, []byte, error) {
	if c.Defined() && VersionIDOf(c) == RootVersion {
		d, commitment, err := ParseRoot(c)
		if err != nil {
			return codecParts{}, nil, err
		}
		profile, _ := Profile(d.Profile)
		backend, _ := backendDescriptorForKind(profile.Algorithm)
		semantic := SemanticKindMap
		if d.Layout == Positional {
			semantic = SemanticKindList
		}
		return codecParts{versionID: d.Version, semantic: semantic, backend: backend}, commitment, nil
	}
	parts, ok := decodeCodec(c.Prefix().Codec)
	if !ok {
		return codecParts{}, nil, fmt.Errorf("not a MALT commitment CID: codec=%x", c.Prefix().Codec)
	}
	decoded, err := mh.Decode(c.Hash())
	if err != nil {
		return codecParts{}, nil, fmt.Errorf("failed to decode multihash: %w", err)
	}
	if decoded.Code != mh.IDENTITY {
		return codecParts{}, nil, fmt.Errorf("expected identity hash, got code=%x", decoded.Code)
	}
	if len(decoded.Digest) != parts.backend.commitmentSize {
		return codecParts{}, nil, fmt.Errorf(
			"invalid %s commitment size: %d, expected %d",
			CodecName(c.Prefix().Codec), len(decoded.Digest), parts.backend.commitmentSize,
		)
	}
	return parts, decoded.Digest, nil
}

// EqualCommitment reports whether a and b use the same commitment backend and
// carry the same commitment bytes. This permits semantic rewrapping (for
// example map to list) without treating equal-length values from different
// backend suites as interchangeable.
func EqualCommitment(a, b cid.Cid) (bool, error) {
	ab, err := ExtractCommitment(a)
	if err != nil {
		return false, err
	}
	bb, err := ExtractCommitment(b)
	if err != nil {
		return false, err
	}
	if profileIdentity(a) != profileIdentity(b) {
		return false, nil
	}
	return bytes.Equal(ab, bb), nil
}

// CodecName returns the locked wire name for a typed MALT multicodec.
func CodecName(codec uint64) string {
	if codec >= 0x300000 && codec <= 0x3002ff {
		layout, aa := Layout((codec>>8)&15), uint8(codec&255)
		if layout == Prefix || (layout == Positional && aa == 0) {
			return fmt.Sprintf("malt-v0-layout%d-aa%02x", layout, aa)
		}
	}
	parts, ok := decodeCodec(codec)
	if !ok {
		return fmt.Sprintf("unknown-%x", codec)
	}
	return fmt.Sprintf("malt-%s-%s", parts.semantic, parts.backend.kind)
}

type codecParts struct {
	versionID uint8
	semantic  SemanticKind
	backend   backendDescriptor
}

func codecFor(semantic SemanticKind, backend BackendKind) (uint64, backendDescriptor, error) {
	return codecForVersion(MALTVersionID, semantic, backend)
}

func codecForVersion(versionID uint8, semantic SemanticKind, backend BackendKind) (uint64, backendDescriptor, error) {
	if versionID != MALTVersionID && versionID != LegacyMALTVersionID {
		return 0, backendDescriptor{}, fmt.Errorf("unsupported typed cid version %d", versionID)
	}
	semanticID, ok := semanticIDForKind(semantic)
	if !ok {
		return 0, backendDescriptor{}, fmt.Errorf("unsupported typed cid semantic kind %q", semantic)
	}
	descriptor, ok := backendDescriptorForKind(backend)
	if !ok {
		return 0, backendDescriptor{}, fmt.Errorf("unsupported typed cid backend %q", backend)
	}
	codec := uint64(codecMaltRootBase) |
		uint64(versionID)<<codecVersionShift |
		uint64(semanticID)<<codecSemanticShift |
		uint64(descriptor.id)
	return codec, descriptor, nil
}

func decodeCodec(codec uint64) (codecParts, bool) {
	if codec < codecMaltRootBase || codec > codecMaltRootMax {
		return codecParts{}, false
	}
	offset := codec - codecMaltRootBase
	versionID := uint8(offset >> codecVersionShift)
	if versionID != MALTVersionID && versionID != LegacyMALTVersionID {
		return codecParts{}, false
	}
	semanticID := uint8((offset >> codecSemanticShift) & 0x0F)
	semantic, ok := semanticKindForID(semanticID)
	if !ok {
		return codecParts{}, false
	}
	descriptor, ok := backendDescriptorForID(uint8(offset & 0xFF))
	if !ok {
		return codecParts{}, false
	}
	reconstructed, _, err := codecForVersion(versionID, semantic, descriptor.kind)
	if err != nil || reconstructed != codec {
		return codecParts{}, false
	}
	return codecParts{versionID: versionID, semantic: semantic, backend: descriptor}, true
}

func semanticIDForKind(kind SemanticKind) (uint8, bool) {
	switch kind {
	case SemanticKindMap:
		return semanticIDMap, true
	case SemanticKindList:
		return semanticIDList, true
	default:
		return 0, false
	}
}

func semanticKindForID(id uint8) (SemanticKind, bool) {
	switch id {
	case semanticIDMap:
		return SemanticKindMap, true
	case semanticIDList:
		return SemanticKindList, true
	default:
		return SemanticKindUnknown, false
	}
}

func backendDescriptorForKind(kind BackendKind) (backendDescriptor, bool) {
	for _, descriptor := range backendRegistry {
		if descriptor.kind == kind {
			return descriptor, true
		}
	}
	return backendDescriptor{}, false
}

func backendDescriptorForID(id uint8) (backendDescriptor, bool) {
	for _, descriptor := range backendRegistry {
		if descriptor.id == id {
			return descriptor, true
		}
	}
	return backendDescriptor{}, false
}

func profileIdentity(root cid.Cid) ProfileID {
	if d, _, err := ParseRoot(root); err == nil {
		return d.Profile
	}
	switch BackendKindOf(root) {
	case BackendKindKZG:
		return KZG4096
	case BackendKindIPA:
		return IPA256
	}
	return 0
}

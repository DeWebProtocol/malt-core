// Package maltcid defines current self-describing MALT Roots and node references.
package maltcid

import (
	"fmt"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

const (
	codecMaltRootBase = 0x300000
	codecMaltRootMax  = 0x30ffff
)

type SemanticKind string

const (
	SemanticKindUnknown SemanticKind = "unknown"
	SemanticKindMap     SemanticKind = "map"
	SemanticKindList    SemanticKind = "list"
)

type BackendKind string

const (
	BackendKindUnknown BackendKind = "unknown"
	BackendKindKZG     BackendKind = "kzg"
	BackendKindIPA     BackendKind = "ipa"
	KZGCommitmentSize              = 48
	IPACommitmentSize              = 32
)

// NewSemanticRoot constructs a V0 Root for the map/list convenience API.
// Typed callers should select an explicit descriptor with NewRoot.
func NewSemanticRoot(kind SemanticKind, backend BackendKind, commitment []byte) (cid.Cid, error) {
	d := RootDescriptor{Layout: Prefix, InputRule: 1}
	switch kind {
	case SemanticKindMap:
	case SemanticKindList:
		d.Layout = Positional
		d.InputRule = 0
	default:
		return cid.Undef, fmt.Errorf("unsupported semantic kind %q", kind)
	}
	switch backend {
	case BackendKindKZG:
		d.Profile = KZG4096
	case BackendKindIPA:
		d.Profile = IPA256
	default:
		return cid.Undef, fmt.Errorf("unsupported backend %q", backend)
	}
	return NewRoot(d, commitment)
}
func newMaltCid(codec uint64, commitment []byte) (cid.Cid, error) {
	digest, err := mh.Encode(commitment, mh.IDENTITY)
	if err != nil {
		return cid.Undef, err
	}
	return cid.NewCidV1(codec, digest), nil
}
func IsMaltCid(c cid.Cid) bool { _, _, err := ParseRoot(c); return err == nil }

// VersionIDOf inspects a codec version without claiming it is supported.
func VersionIDOf(c cid.Cid) uint8 {
	if !c.Defined() {
		return 0
	}
	codec := c.Prefix().Codec
	if codec < 0x300000 || codec > 0x30ffff {
		return 0
	}
	return uint8(codec >> 12 & 15)
}
func SemanticKindOf(c cid.Cid) SemanticKind {
	d, _, err := ParseRoot(c)
	if err != nil {
		return SemanticKindUnknown
	}
	if d.Layout == Prefix {
		return SemanticKindMap
	}
	return SemanticKindList
}
func BackendKindOf(c cid.Cid) BackendKind {
	d, _, err := ParseRoot(c)
	if err != nil {
		return BackendKindUnknown
	}
	p, _ := Profile(d.Profile)
	return p.Algorithm
}
func GetMaltCodec(c cid.Cid) uint64 {
	if IsMaltCid(c) {
		return c.Prefix().Codec
	}
	return 0
}
func ExtractCommitment(c cid.Cid) ([]byte, error) { _, data, err := ParseRoot(c); return data, err }
func CodecName(codec uint64) string {
	if codec >= 0x300100 && codec <= 0x3001ff || codec == 0x300200 {
		return fmt.Sprintf("malt-v0-layout%d-aa%02x", (codec>>8)&15, codec&255)
	}
	return fmt.Sprintf("unknown-%x", codec)
}

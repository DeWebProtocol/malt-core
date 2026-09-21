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

type BackendKind string

const (
	BackendKindUnknown BackendKind = "unknown"
	BackendKindKZG     BackendKind = "kzg"
	BackendKindIPA     BackendKind = "ipa"
	KZGCommitmentSize              = 48
	IPACommitmentSize              = 32
)

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

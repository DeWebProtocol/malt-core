package maltcid

import (
	"bytes"
	"encoding/binary"
	"fmt"

	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

// RootVersion stays zero until the maintainer explicitly declares production
// readiness. It is independent of CIDv1, SDK versions and historical Roots.
const RootVersion uint8 = 0

// Layout selects how coordinates are organized within one authentication tree.
// Application ArcSet organization (flat or compositional) is not a Root field.
type Layout uint8

const (
	Prefix     Layout = 1
	Positional Layout = 2
)

type ProfileID uint64

const (
	KZG4096 ProfileID = 1
	IPA256  ProfileID = 2
)

// VCProfile fixes cryptographic identity, not execution/precomputation policy.
// IDs are allocations of this experimental format, never algorithm aliases.
type VCProfile struct {
	ID               ProfileID
	Algorithm        BackendKind
	ParametersSHA256 string
	CommitmentSize   int
	Slots            int
	CellEncoding     string
	ProofEncoding    string
}

func Profile(id ProfileID) (VCProfile, error) {
	switch id {
	case KZG4096:
		return VCProfile{id, BackendKindKZG, "0229b43f4fac9b17374809520eb621b5ee1a7f74547e7d36918e7d4b122e178d", 48, 4096, "malt.kzg.cell-sha256/v1", "malt.kzg.index/v1"}, nil
	case IPA256:
		return VCProfile{id, BackendKindIPA, "3799df0a77d1843b13a3a08744165180a12e1cd2dca529bee64ad691ac63adaf", 32, 256, "malt.ipa.cell-sha256/v1", "malt.ipa.index/v1"}, nil
	default:
		return VCProfile{}, fmt.Errorf("unsupported VC profile %d", id)
	}
}

// RootDescriptor records derivation, authentication layout and exact VC profile. Parsing checks
// structural encoding; the outer engine checks derivation support and compatibility.
type RootDescriptor struct {
	Version           uint8     `json:"version" schema:"optional"`
	Layout            Layout    `json:"layout"`
	DerivationProfile uint8     `json:"derivation_profile"`
	Profile           ProfileID `json:"vc_profile"`
}

func (d RootDescriptor) Validate() error {
	if d.Version != RootVersion {
		return fmt.Errorf("unsupported Root version %d", d.Version)
	}
	if d.Layout != Prefix && d.Layout != Positional {
		return fmt.Errorf("unsupported layout %d", d.Layout)
	}
	_, err := Profile(d.Profile)
	return err
}

// Multicommitment is profile-id || commitment-length || commitment. Integers
// use minimal unsigned varints and the exact profile fixes the allowed length.
func Multicommitment(id ProfileID, commitment []byte) ([]byte, error) {
	p, err := Profile(id)
	if err != nil {
		return nil, err
	}
	if len(commitment) != p.CommitmentSize {
		return nil, fmt.Errorf("profile %d requires %d commitment bytes", id, p.CommitmentSize)
	}
	out := binary.AppendUvarint(nil, uint64(id))
	out = binary.AppendUvarint(out, uint64(len(commitment)))
	return append(out, commitment...), nil
}

func ParseMulticommitment(data []byte) (ProfileID, []byte, error) {
	id, n, err := canonicalUvarint(data)
	if err != nil {
		return 0, nil, err
	}
	size, m, err := canonicalUvarint(data[n:])
	if err != nil {
		return 0, nil, err
	}
	p, err := Profile(ProfileID(id))
	if err != nil {
		return 0, nil, err
	}
	if size != uint64(p.CommitmentSize) || len(data)-n-m != p.CommitmentSize {
		return 0, nil, fmt.Errorf("multicommitment length does not match profile %d", id)
	}
	return ProfileID(id), bytes.Clone(data[n+m:]), nil
}

func canonicalUvarint(data []byte) (uint64, int, error) {
	value, n := binary.Uvarint(data)
	if n <= 0 || n > 9 || len(binary.AppendUvarint(nil, value)) != n {
		return 0, 0, fmt.Errorf("invalid or nonminimal unsigned varint")
	}
	return value, n, nil
}

// NewRoot constructs CIDv1(codec=0x30VLAA, identity(multicommitment)).
func NewRoot(d RootDescriptor, commitment []byte) (cid.Cid, error) {
	if err := d.Validate(); err != nil {
		return cid.Undef, err
	}
	mc, err := Multicommitment(d.Profile, commitment)
	if err != nil {
		return cid.Undef, err
	}
	return newMaltCid(uint64(codecMaltRootBase)|uint64(d.Version)<<12|uint64(d.Layout)<<8|uint64(d.DerivationProfile), mc)
}

func ParseRoot(root cid.Cid) (RootDescriptor, []byte, error) {
	if !root.Defined() || root.Version() != 1 {
		return RootDescriptor{}, nil, fmt.Errorf("Root requires CIDv1")
	}
	codec := root.Prefix().Codec
	if codec < codecMaltRootBase || codec > codecMaltRootMax {
		return RootDescriptor{}, nil, fmt.Errorf("not a MALT Root codec")
	}
	d := RootDescriptor{Version: uint8((codec >> 12) & 15), Layout: Layout((codec >> 8) & 15), DerivationProfile: uint8(codec)}
	if d.Version != RootVersion {
		return RootDescriptor{}, nil, fmt.Errorf("unsupported Root version %d", d.Version)
	}
	hash, err := mh.Decode(root.Hash())
	if err != nil || hash.Code != mh.IDENTITY {
		return RootDescriptor{}, nil, fmt.Errorf("Root requires identity multihash")
	}
	d.Profile, hash.Digest, err = ParseMulticommitment(hash.Digest)
	if err != nil {
		return RootDescriptor{}, nil, err
	}
	if err := d.Validate(); err != nil {
		return RootDescriptor{}, nil, err
	}
	canonical, err := NewRoot(d, hash.Digest)
	if err != nil || !bytes.Equal(canonical.Bytes(), root.Bytes()) {
		return RootDescriptor{}, nil, fmt.Errorf("noncanonical Root")
	}
	return d, hash.Digest, nil
}

// NodeRef identifies an INTERNAL authentication vector. Its identity includes
// node encoding/layout and VC profile, and deliberately excludes AA. It is
// not an application Root and must never be accepted as one.
type NodeRef struct {
	Layout     Layout
	Profile    ProfileID
	Commitment []byte
}

func (r NodeRef) Bytes() ([]byte, error) {
	if r.Layout != Prefix && r.Layout != Positional {
		return nil, fmt.Errorf("invalid internal layout")
	}
	mc, err := Multicommitment(r.Profile, r.Commitment)
	if err != nil {
		return nil, err
	}
	return append([]byte{'M', 'N', 0, byte(r.Layout)}, mc...), nil
}
func ParseNodeRef(data []byte) (NodeRef, error) {
	if len(data) < 4 || !bytes.Equal(data[:3], []byte{'M', 'N', 0}) {
		return NodeRef{}, fmt.Errorf("invalid internal node reference")
	}
	r := NodeRef{Layout: Layout(data[3])}
	var err error
	r.Profile, r.Commitment, err = ParseMulticommitment(data[4:])
	if err != nil {
		return NodeRef{}, err
	}
	if _, err := r.Bytes(); err != nil {
		return NodeRef{}, err
	}
	return r, nil
}

func RootNode(root cid.Cid) (NodeRef, RootDescriptor, error) {
	d, c, err := ParseRoot(root)
	return NodeRef{Layout: d.Layout, Profile: d.Profile, Commitment: c}, d, err
}

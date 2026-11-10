package maltcid_test

import (
	"testing"

	"github.com/dewebprotocol/malt-core/derivation"
	"github.com/dewebprotocol/malt-core/maltcid"
	cid "github.com/ipfs/go-cid"
)

func TestCurrentRootClassification(t *testing.T) {
	for _, tc := range []struct {
		layout     maltcid.Layout
		derivation derivation.ProfileID
		name       string
	}{
		{maltcid.Map, derivation.SHA256, "malt-v0-layout1-derivation04"},
		{maltcid.Map, derivation.Direct, "malt-v0-layout1-derivation03"},
		{maltcid.List, derivation.Direct, "malt-v0-layout2-derivation03"},
	} {
		for _, profile := range []maltcid.ProfileID{maltcid.KZG4096, maltcid.IPA256} {
			p, err := maltcid.Profile(profile)
			if err != nil {
				t.Fatal(err)
			}
			d := maltcid.RootDescriptor{DerivationProfile: uint8(tc.derivation), Layout: tc.layout, Profile: profile}
			size := maltcid.KZGCommitmentSize
			if profile == maltcid.IPA256 {
				size = maltcid.IPACommitmentSize
			}
			root, err := maltcid.NewRoot(d, make([]byte, size))
			if err != nil {
				t.Fatal(err)
			}
			decoded, _, err := maltcid.ParseRoot(root)
			if err != nil || decoded != d || !maltcid.IsMaltCid(root) || maltcid.VersionIDOf(root) != 0 || maltcid.BackendKindOf(root) != p.Algorithm {
				t.Fatalf("Root descriptor classification: %v", err)
			}
			if got := maltcid.CodecName(root.Prefix().Codec); got != tc.name {
				t.Fatalf("CodecName(%#x) = %q, want %q", root.Prefix().Codec, got, tc.name)
			}
		}
	}
}

func TestRootClassificationRequiresCurrentDescriptor(t *testing.T) {
	root, err := maltcid.NewRoot(maltcid.RootDescriptor{
		Version: maltcid.RootVersion, Layout: maltcid.Map,
		DerivationProfile: uint8(derivation.SHA256), Profile: maltcid.IPA256,
	}, make([]byte, maltcid.IPACommitmentSize))
	if err != nil {
		t.Fatal(err)
	}
	codec := root.Prefix().Codec
	for name, invalidCodec := range map[string]uint64{
		"unknown version": codec&^0xf000 | 0xf000,
		"unknown layout":  codec&^0xf00 | 0xf00,
		"non-MALT codec":  cid.Raw,
	} {
		t.Run(name, func(t *testing.T) {
			invalid := cid.NewCidV1(invalidCodec, root.Hash())
			if _, _, err := maltcid.ParseRoot(invalid); err == nil {
				t.Fatal("invalid descriptor parsed")
			}
			if maltcid.IsMaltCid(invalid) || maltcid.BackendKindOf(invalid) != maltcid.BackendKindUnknown || maltcid.GetMaltCodec(invalid) != 0 {
				t.Fatal("invalid descriptor advertised as a supported Root")
			}
			if _, err := maltcid.ExtractCommitment(invalid); err == nil {
				t.Fatal("commitment extracted from invalid descriptor")
			}
		})
	}
}

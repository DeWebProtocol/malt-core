package maltcid_test

import (
	"fmt"
	"testing"

	"github.com/dewebprotocol/malt-core/derivation"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

func TestCurrentRootClassification(t *testing.T) {
	for _, tc := range []struct {
		layout     maltcid.Layout
		derivation derivation.ProfileID
		name       string
	}{
		{maltcid.Prefix, derivation.SHA256, "malt-v0-layout1-derivation04"},
		{maltcid.Prefix, derivation.Direct, "malt-v0-layout1-derivation03"},
		{maltcid.Positional, derivation.Direct, "malt-v0-layout2-derivation03"},
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

func TestHistoricalRootsAreRejected(t *testing.T) {
	for _, codec := range []uint64{0x300001, 0x300002, 0x300003, 0x300004, 0x302101, 0x302102, 0x302201, 0x302202, 0x303101, 0x303102, 0x303201, 0x303202} {
		t.Run(fmt.Sprintf("%x", codec), func(t *testing.T) {
			size := maltcid.KZGCommitmentSize
			if codec&1 == 0 {
				size = maltcid.IPACommitmentSize
			}
			hash, err := mh.Encode(make([]byte, size), mh.IDENTITY)
			if err != nil {
				t.Fatal(err)
			}
			root := cid.NewCidV1(codec, hash)
			if _, _, err := maltcid.ParseRoot(root); err == nil {
				t.Fatal("historical Root parsed as current")
			}
			if maltcid.IsMaltCid(root) || maltcid.BackendKindOf(root) != maltcid.BackendKindUnknown || maltcid.GetMaltCodec(root) != 0 {
				t.Fatal("historical Root advertised as a supported Root")
			}
			if _, err := maltcid.ExtractCommitment(root); err == nil {
				t.Fatal("historical commitment extracted by current parser")
			}
		})
	}
}

package maltcid_test

import (
	"bytes"
	"testing"

	"github.com/dewebprotocol/malt-core/derivation"
	"github.com/dewebprotocol/malt-core/maltcid"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

func TestSelfDescribingRoot(t *testing.T) {
	for _, id := range []maltcid.ProfileID{maltcid.KZG4096, maltcid.IPA256} {
		p, _ := maltcid.Profile(id)
		c := make([]byte, p.CommitmentSize)
		c[0] = 42
		d := maltcid.RootDescriptor{Layout: maltcid.Map, DerivationProfile: uint8(derivation.SHA256), Profile: id}
		root, err := maltcid.NewRoot(d, c)
		if err != nil {
			t.Fatal(err)
		}
		got, value, err := maltcid.ParseRoot(root)
		if err != nil || got != d || !bytes.Equal(c, value) {
			t.Fatalf("round trip %v", err)
		}
		if root.Prefix().Codec != 0x300104 || maltcid.VersionIDOf(root) != 0 || !maltcid.IsMaltCid(root) {
			t.Fatal("wrong Root codec")
		}
		ref, _, _ := maltcid.RootNode(root)
		raw, _ := ref.Bytes()
		parsed, err := maltcid.ParseNodeRef(raw)
		if err != nil || parsed.Profile != id {
			t.Fatal(err)
		}
		d.DerivationProfile = uint8(derivation.Direct)
		other, _ := maltcid.NewRoot(d, c)
		ref2, _, _ := maltcid.RootNode(other)
		raw2, _ := ref2.Bytes()
		if root.Equals(other) || !bytes.Equal(raw, raw2) {
			t.Fatal("AA leaked into internal node identity")
		}
		bad := append([]byte{byte(id) | 128, 0, byte(p.CommitmentSize)}, c...)
		hash, _ := mh.Encode(append([]byte("malt:root\x00"), bad...), mh.IDENTITY)
		if _, _, err := maltcid.ParseRoot(cid.NewCidV1(0x300104, hash)); err == nil {
			t.Fatal("nonminimal profile ID accepted")
		}
	}
	if _, err := maltcid.NewRoot(maltcid.RootDescriptor{DerivationProfile: uint8(derivation.Direct), Version: 1, Layout: maltcid.Map, Profile: maltcid.IPA256}, make([]byte, 32)); err == nil {
		t.Fatal("production V=1 enabled")
	}
}

func TestSupersededLayoutIDsAreRejected(t *testing.T) {
	for _, profile := range []maltcid.ProfileID{maltcid.KZG4096, maltcid.IPA256} {
		p, _ := maltcid.Profile(profile)
		commitment := make([]byte, p.CommitmentSize)
		mc, err := maltcid.Multicommitment(profile, commitment)
		if err != nil {
			t.Fatal(err)
		}
		hash, _ := mh.Encode(append([]byte("malt:root\x00"), mc...), mh.IDENTITY)
		for _, layout := range []byte{3, 4} {
			root := cid.NewCidV1(0x300000|uint64(layout)<<8|uint64(derivation.Direct), hash)
			if _, _, err := maltcid.ParseRoot(root); err == nil || maltcid.IsMaltCid(root) {
				t.Fatalf("superseded layout %d Root accepted", layout)
			}
			ref := append(append([]byte("malt:node\x00"), layout), mc...)
			if _, err := maltcid.ParseNodeRef(ref); err == nil {
				t.Fatalf("superseded layout %d internal node accepted", layout)
			}
		}
	}
}

func TestHistoricalV0FramingIsRejected(t *testing.T) {
	for _, profile := range []maltcid.ProfileID{maltcid.KZG4096, maltcid.IPA256} {
		p, _ := maltcid.Profile(profile)
		mc, err := maltcid.Multicommitment(profile, make([]byte, p.CommitmentSize))
		if err != nil {
			t.Fatal(err)
		}
		for _, layout := range []byte{1, 2, 3, 4} {
			hash, _ := mh.Encode(mc, mh.IDENTITY)
			root := cid.NewCidV1(0x300000|uint64(layout)<<8|uint64(derivation.Direct), hash)
			if _, _, err := maltcid.ParseRoot(root); err == nil {
				t.Fatalf("historical V0 layout %d Root accepted without the current domain", layout)
			}
			if _, err := maltcid.ParseNodeRef(append([]byte{'M', 'N', 0, layout}, mc...)); err == nil {
				t.Fatalf("historical layout %d node accepted without the current domain", layout)
			}
		}
	}
}

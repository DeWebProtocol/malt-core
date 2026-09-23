package maltcid_test

import (
	"bytes"
	"testing"

	"github.com/dewebprotocol/malt-core/derivation"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

func TestSelfDescribingRoot(t *testing.T) {
	for _, id := range []maltcid.ProfileID{maltcid.KZG4096, maltcid.IPA256} {
		p, _ := maltcid.Profile(id)
		c := make([]byte, p.CommitmentSize)
		c[0] = 42
		d := maltcid.RootDescriptor{Layout: maltcid.Prefix, DerivationProfile: uint8(derivation.SHA256), Profile: id}
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
		hash, _ := mh.Encode(bad, mh.IDENTITY)
		if _, _, err := maltcid.ParseRoot(cid.NewCidV1(0x300104, hash)); err == nil {
			t.Fatal("nonminimal profile ID accepted")
		}
	}
	if _, err := maltcid.NewRoot(maltcid.RootDescriptor{DerivationProfile: uint8(derivation.Direct), Version: 1, Layout: maltcid.Prefix, Profile: maltcid.IPA256}, make([]byte, 32)); err == nil {
		t.Fatal("production V=1 enabled")
	}
}

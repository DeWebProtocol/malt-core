package proofwire

import (
	"testing"

	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

func TestCIDMustConsumeItsFullEncoding(t *testing.T) {
	// identity multihash with a zero-length digest and an extra byte
	malformed := cid.NewCidV1(cid.Raw, mh.Multihash{0, 0, 1})
	var s Stream
	s.CID(malformed)
	if s.Err == nil {
		t.Fatal("accepted trailing bytes inside a CID field")
	}
}

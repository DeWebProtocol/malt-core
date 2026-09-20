package maltcid_test

import (
	"fmt"
	"testing"

	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

func TestCurrentSemanticRootClassification(t *testing.T) {
	for _, kind := range []maltcid.SemanticKind{maltcid.SemanticKindMap, maltcid.SemanticKindList} {
		for _, backend := range []maltcid.BackendKind{maltcid.BackendKindKZG, maltcid.BackendKindIPA} {
			size := maltcid.KZGCommitmentSize
			if backend == maltcid.BackendKindIPA {
				size = maltcid.IPACommitmentSize
			}
			root, err := maltcid.NewSemanticRoot(kind, backend, make([]byte, size))
			if err != nil {
				t.Fatal(err)
			}
			if !maltcid.IsMaltCid(root) || maltcid.VersionIDOf(root) != 0 || maltcid.SemanticKindOf(root) != kind || maltcid.BackendKindOf(root) != backend {
				t.Fatalf("incorrect classification of %s/%s: %s", kind, backend, root)
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
			if maltcid.IsMaltCid(root) || maltcid.SemanticKindOf(root) != maltcid.SemanticKindUnknown || maltcid.BackendKindOf(root) != maltcid.BackendKindUnknown || maltcid.GetMaltCodec(root) != 0 {
				t.Fatal("historical Root advertised as a supported semantic root")
			}
			if _, err := maltcid.ExtractCommitment(root); err == nil {
				t.Fatal("historical commitment extracted by current parser")
			}
		})
	}
}

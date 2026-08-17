package verifier

import (
	"context"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/proof/prooflist"
	structure "github.com/dewebprotocol/malt-core/auth/semantic"
	"github.com/dewebprotocol/malt-core/auth/semantic/list"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

func TestVerifyProofListListStructureVerifiesListIndexStep(t *testing.T) {
	root := testCID(t, "list-root")
	target := testCID(t, "segment")
	index := uint64(3)
	length := uint64(9)
	lists := &fakeListSemantics{valid: true}

	valid, err := VerifyProofListListStructure(lists, prooflist.Step{
		From:            root,
		Index:           &index,
		Length:          &length,
		Target:          target,
		EvidenceBackend: "list",
		Proof:           []byte("index-proof"),
	}, 2)
	if err != nil {
		t.Fatalf("VerifyProofListListStructure returned error: %v", err)
	}
	if !valid {
		t.Fatal("VerifyProofListListStructure returned invalid for a valid list index step")
	}
	if got, want := len(lists.verifyCalls), 1; got != want {
		t.Fatalf("Verify calls = %d, want %d", got, want)
	}
	call := lists.verifyCalls[0]
	if !call.root.Equals(root) {
		t.Fatalf("Verify root = %s, want %s", call.root, root)
	}
	if call.index != index {
		t.Fatalf("Verify index = %d, want %d", call.index, index)
	}
	if !call.expected.Key.Equals(target) || call.expected.Length != length {
		t.Fatalf("Verify expected = %+v, want target %s length %d", call.expected, target, length)
	}
}

func TestVerifyProofListListStructureVerifiesMeasuredListRangeStep(t *testing.T) {
	root := testCID(t, "list-root")
	segA := testCID(t, "segment-a")
	segB := testCID(t, "segment-b")
	start := uint64(4)
	end := uint64(12)
	childCount := uint64(2)
	totalSize := uint64(16)
	chunkSize := uint64(8)
	lists := &fakeListSemantics{valid: true}

	valid, err := VerifyProofListListStructure(lists, prooflist.Step{
		From:            root,
		Target:          root,
		Start:           &start,
		End:             &end,
		ChildCount:      &childCount,
		TotalSize:       &totalSize,
		ChunkSize:       &chunkSize,
		Segments:        []cid.Cid{segA, segB},
		EvidenceBackend: "measured_list",
		Proof:           []byte("range-proof"),
	}, 5)
	if err != nil {
		t.Fatalf("VerifyProofListListStructure returned error: %v", err)
	}
	if !valid {
		t.Fatal("VerifyProofListListStructure returned invalid for a valid measured-list range step")
	}
	if got, want := len(lists.verifyRangeCalls), 1; got != want {
		t.Fatalf("VerifyRange calls = %d, want %d", got, want)
	}
	call := lists.verifyRangeCalls[0]
	if !call.root.Equals(root) {
		t.Fatalf("VerifyRange root = %s, want %s", call.root, root)
	}
	if call.start != start || call.end == nil || *call.end != end {
		t.Fatalf("VerifyRange bounds = [%d,%v), want [%d,%d)", call.start, call.end, start, end)
	}
	if call.expected.Metadata.ChildCount != childCount || call.expected.Metadata.TotalSize != totalSize || call.expected.Metadata.ChunkSize != chunkSize {
		t.Fatalf("VerifyRange metadata = %+v, want child_count=%d total_size=%d chunk_size=%d", call.expected.Metadata, childCount, totalSize, chunkSize)
	}
	if got, want := len(call.expected.Segments), 2; got != want {
		t.Fatalf("VerifyRange segments = %d, want %d", got, want)
	}
}

type listVerifyCall struct {
	root     cid.Cid
	index    uint64
	expected list.Query
	proof    structure.Proof
}

type rangeVerifyCall struct {
	root     cid.Cid
	start    uint64
	end      *uint64
	expected list.RangeResult
	proof    structure.Proof
}

type fakeListSemantics struct {
	valid            bool
	err              error
	verifyCalls      []listVerifyCall
	verifyRangeCalls []rangeVerifyCall
}

func (l *fakeListSemantics) Commitment() *list.Commitment {
	return nil
}

func (l *fakeListSemantics) Commit(context.Context, string, list.View) (cid.Cid, error) {
	return cid.Undef, nil
}

func (l *fakeListSemantics) Prove(context.Context, string, cid.Cid, uint64) (list.Query, structure.Proof, error) {
	return list.Query{}, nil, nil
}

func (l *fakeListSemantics) Verify(root cid.Cid, index uint64, expected list.Query, proof structure.Proof) (bool, error) {
	l.verifyCalls = append(l.verifyCalls, listVerifyCall{
		root:     root,
		index:    index,
		expected: expected,
		proof:    proof,
	})
	return l.valid, l.err
}

func (l *fakeListSemantics) Replace(context.Context, string, cid.Cid, uint64, cid.Cid, cid.Cid) (cid.Cid, error) {
	return cid.Undef, nil
}

func (l *fakeListSemantics) Append(context.Context, string, cid.Cid, cid.Cid) (cid.Cid, uint64, error) {
	return cid.Undef, 0, nil
}

func (l *fakeListSemantics) Truncate(context.Context, string, cid.Cid, uint64) (cid.Cid, error) {
	return cid.Undef, nil
}

func (l *fakeListSemantics) ProveRange(context.Context, string, cid.Cid, uint64, *uint64) (list.RangeResult, structure.Proof, error) {
	return list.RangeResult{}, nil, nil
}

func (l *fakeListSemantics) VerifyRange(root cid.Cid, start uint64, end *uint64, expected list.RangeResult, proof structure.Proof) (bool, error) {
	l.verifyRangeCalls = append(l.verifyRangeCalls, rangeVerifyCall{
		root:     root,
		start:    start,
		end:      end,
		expected: expected,
		proof:    proof,
	})
	return l.valid, l.err
}

func testCID(t *testing.T, seed string) cid.Cid {
	t.Helper()
	sum, err := mh.Sum([]byte(seed), mh.SHA2_256, -1)
	if err != nil {
		t.Fatalf("hash seed: %v", err)
	}
	return cid.NewCidV1(cid.Raw, sum)
}

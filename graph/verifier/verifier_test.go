package verifier

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	"github.com/dewebprotocol/malt-core/auth/proof/prooflist"
	structure "github.com/dewebprotocol/malt-core/auth/semantic"
	"github.com/dewebprotocol/malt-core/auth/semantic/list"
	"github.com/dewebprotocol/malt-core/auth/semantic/mapping"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

func TestVerifyProofListAcceptsValidMapPath(t *testing.T) {
	root := testCID(t, "root")
	dir := testCID(t, "dir")
	file := testCID(t, "file")
	rt := newFakeRuntime()
	pl := prooflist.ProofList{
		Root:  root,
		Query: "dir/file",
		Steps: []prooflist.Step{
			mapStep(root, "dir", dir),
			mapStep(dir, "file", file),
		},
	}

	valid, err := New(rt).VerifyProofList(context.Background(), pl)
	if err != nil {
		t.Fatalf("VerifyProofList returned error: %v", err)
	}
	if !valid {
		t.Fatal("VerifyProofList returned invalid for a valid map path")
	}
	if got, want := len(rt.maps.verifyCalls), 2; got != want {
		t.Fatalf("map verify calls = %d, want %d", got, want)
	}
	if got := rt.maps.verifyCalls[0].key.String(); got != "dir" {
		t.Fatalf("first verified key = %q, want dir", got)
	}
	if got := rt.maps.verifyCalls[1].key.String(); got != "file" {
		t.Fatalf("second verified key = %q, want file", got)
	}
}

func TestVerifyProofListRejectsQueryMismatch(t *testing.T) {
	root := testCID(t, "root")
	target := testCID(t, "target")
	pl := prooflist.ProofList{
		Root:  root,
		Query: "other",
		Steps: []prooflist.Step{
			mapStep(root, "name", target),
		},
	}

	valid, err := New(newFakeRuntime()).VerifyProofList(context.Background(), pl)
	if err == nil {
		t.Fatal("VerifyProofList returned nil error for a query mismatch")
	}
	if valid {
		t.Fatal("VerifyProofList returned valid for a query mismatch")
	}
	if !strings.Contains(err.Error(), "does not match ordered traversal path") {
		t.Fatalf("query mismatch error = %q, want traversal path error", err.Error())
	}
}

func TestVerifyProofListRejectsTraversalAfterPayloadBinding(t *testing.T) {
	root := testCID(t, "root")
	payload := testCID(t, "payload")
	child := testCID(t, "child")
	pl := prooflist.ProofList{
		Root:  root,
		Query: "@payload/child",
		Steps: []prooflist.Step{
			{
				Kind:            prooflist.KindPayloadBinding,
				From:            root,
				Path:            "@payload",
				Target:          payload,
				EvidenceKind:    "structure",
				EvidenceBackend: "map",
				Proof:           []byte("payload-proof"),
			},
			mapStep(payload, "child", child),
		},
	}

	valid, err := New(newFakeRuntime()).VerifyProofList(context.Background(), pl)
	if err == nil {
		t.Fatal("VerifyProofList returned nil error for traversal after @payload")
	}
	if valid {
		t.Fatal("VerifyProofList returned valid for traversal after @payload")
	}
	if !strings.Contains(err.Error(), "appears after terminal @payload binding") {
		t.Fatalf("payload traversal error = %q, want terminal binding error", err.Error())
	}
}

func TestVerifyProofListVerifiesMeasuredListStep(t *testing.T) {
	root := testCID(t, "list-root")
	segA := testCID(t, "segment-a")
	segB := testCID(t, "segment-b")
	start := uint64(2)
	end := uint64(10)
	childCount := uint64(2)
	totalSize := uint64(16)
	chunkSize := uint64(8)
	rt := newFakeRuntime()
	pl := prooflist.ProofList{
		Root: root,
		Steps: []prooflist.Step{
			{
				Kind:            prooflist.KindListRange,
				From:            root,
				Target:          root,
				Start:           &start,
				End:             &end,
				ChildCount:      &childCount,
				TotalSize:       &totalSize,
				ChunkSize:       &chunkSize,
				Segments:        []cid.Cid{segA, segB},
				EvidenceKind:    "structure",
				EvidenceBackend: "measured_list",
				Proof:           []byte("range-proof"),
			},
		},
	}

	valid, err := New(rt).VerifyProofList(context.Background(), pl)
	if err != nil {
		t.Fatalf("VerifyProofList returned error: %v", err)
	}
	if !valid {
		t.Fatal("VerifyProofList returned invalid for a measured-list range step")
	}
	if got, want := len(rt.lists.verifyRangeCalls), 1; got != want {
		t.Fatalf("range verify calls = %d, want %d", got, want)
	}
	call := rt.lists.verifyRangeCalls[0]
	if call.start != start || call.end == nil || *call.end != end {
		t.Fatalf("range verify bounds = [%d,%v), want [%d,%d)", call.start, call.end, start, end)
	}
	if got := len(call.expected.Segments); got != 2 {
		t.Fatalf("range verify segments = %d, want 2", got)
	}
}

func TestVerifyProofListRejectsMalformedProofList(t *testing.T) {
	pl := prooflist.ProofList{
		Root: testCID(t, "root"),
	}

	valid, err := New(newFakeRuntime()).VerifyProofList(context.Background(), pl)
	if err == nil {
		t.Fatal("VerifyProofList returned nil error for an empty ProofList")
	}
	if valid {
		t.Fatal("VerifyProofList returned valid for an empty ProofList")
	}
	if !strings.Contains(err.Error(), "steps are empty") {
		t.Fatalf("malformed prooflist error = %q, want empty steps error", err.Error())
	}
}

func mapStep(from cid.Cid, path string, target cid.Cid) prooflist.Step {
	return prooflist.Step{
		Kind:            prooflist.KindMapStep,
		From:            from,
		Path:            path,
		Target:          target,
		EvidenceKind:    "structure",
		EvidenceBackend: "map",
		Proof:           []byte("map-proof"),
	}
}

func testCID(t *testing.T, seed string) cid.Cid {
	t.Helper()
	sum, err := mh.Sum([]byte(seed), mh.SHA2_256, -1)
	if err != nil {
		t.Fatalf("hash seed: %v", err)
	}
	return cid.NewCidV1(cid.Raw, sum)
}

type fakeRuntime struct {
	maps  *fakeMapSemantics
	lists *fakeListSemantics
}

func newFakeRuntime() *fakeRuntime {
	return &fakeRuntime{
		maps:  &fakeMapSemantics{valid: true},
		lists: &fakeListSemantics{valid: true},
	}
}

func (r *fakeRuntime) Semantic() mapping.Semantics {
	return r.maps
}

func (r *fakeRuntime) ListSemantic() list.Semantics {
	return r.lists
}

type mapVerifyCall struct {
	root     cid.Cid
	key      arcset.Path
	expected mapping.Binding
	proof    structure.Proof
}

type fakeMapSemantics struct {
	valid       bool
	err         error
	verifyCalls []mapVerifyCall
}

func (m *fakeMapSemantics) Commitment() *mapping.Commitment {
	return nil
}

func (m *fakeMapSemantics) Commit(context.Context, string, mapping.View) (cid.Cid, error) {
	return cid.Undef, errors.New("Commit should not be called")
}

func (m *fakeMapSemantics) Prove(context.Context, string, cid.Cid, arcset.Path) (mapping.Binding, structure.Proof, error) {
	return mapping.Binding{}, nil, errors.New("Prove should not be called")
}

func (m *fakeMapSemantics) Verify(root cid.Cid, key arcset.Path, expected mapping.Binding, proof structure.Proof) (bool, error) {
	m.verifyCalls = append(m.verifyCalls, mapVerifyCall{
		root:     root,
		key:      key,
		expected: expected,
		proof:    proof,
	})
	return m.valid, m.err
}

func (m *fakeMapSemantics) Update(context.Context, string, cid.Cid, arcset.Path, cid.Cid, cid.Cid) (cid.Cid, error) {
	return cid.Undef, errors.New("Update should not be called")
}

func (m *fakeMapSemantics) BatchUpdate(context.Context, string, cid.Cid, []mapping.BatchUpdate) (cid.Cid, error) {
	return cid.Undef, errors.New("BatchUpdate should not be called")
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
	verifyRangeCalls []rangeVerifyCall
}

func (l *fakeListSemantics) Commitment() *list.Commitment {
	return nil
}

func (l *fakeListSemantics) Commit(context.Context, string, list.View) (cid.Cid, error) {
	return cid.Undef, errors.New("Commit should not be called")
}

func (l *fakeListSemantics) Prove(context.Context, string, cid.Cid, uint64) (list.Query, structure.Proof, error) {
	return list.Query{}, nil, errors.New("Prove should not be called")
}

func (l *fakeListSemantics) Verify(cid.Cid, uint64, list.Query, structure.Proof) (bool, error) {
	return l.valid, l.err
}

func (l *fakeListSemantics) Replace(context.Context, string, cid.Cid, uint64, cid.Cid, cid.Cid) (cid.Cid, error) {
	return cid.Undef, errors.New("Replace should not be called")
}

func (l *fakeListSemantics) Append(context.Context, string, cid.Cid, cid.Cid) (cid.Cid, uint64, error) {
	return cid.Undef, 0, errors.New("Append should not be called")
}

func (l *fakeListSemantics) Truncate(context.Context, string, cid.Cid, uint64) (cid.Cid, error) {
	return cid.Undef, errors.New("Truncate should not be called")
}

func (l *fakeListSemantics) ProveRange(context.Context, string, cid.Cid, uint64, *uint64) (list.RangeResult, structure.Proof, error) {
	return list.RangeResult{}, nil, errors.New("ProveRange should not be called")
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

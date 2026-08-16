package mapping

import (
	"context"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

func TestCommitmentCommitAuthenticatesKeys(t *testing.T) {
	handler, err := NewCommitment(testScheme{})
	if err != nil {
		t.Fatalf("NewCommitment failed: %v", err)
	}

	valueA := testCID(t, "value-a")
	valueB := testCID(t, "value-b")
	first, err := handler.Commit(context.Background(), NewViewFrom(map[string]cid.Cid{
		"a": valueA,
		"b": valueB,
	}))
	if err != nil {
		t.Fatalf("Commit(first) failed: %v", err)
	}
	second, err := handler.Commit(context.Background(), NewViewFrom(map[string]cid.Cid{
		"c": valueA,
		"d": valueB,
	}))
	if err != nil {
		t.Fatalf("Commit(second) failed: %v", err)
	}
	if first.Equals(second) {
		t.Fatal("different keys with the same ordered values produced the same root")
	}
}

func TestCommitmentCommitProveSlotRoundTrip(t *testing.T) {
	handler, err := NewCommitment(testScheme{})
	if err != nil {
		t.Fatalf("NewCommitment failed: %v", err)
	}

	keyA := arcset.CanonicalizePath("a")
	keyB := arcset.CanonicalizePath("b")
	valueA := testCID(t, "value-a")
	valueB := testCID(t, "value-b")
	root, err := handler.Commit(context.Background(), NewViewFromPaths(map[arcset.Path]cid.Cid{
		keyA: valueA,
		keyB: valueB,
	}))
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	slotA, err := BindingCID(keyA, valueA)
	if err != nil {
		t.Fatalf("BindingCID(a) failed: %v", err)
	}
	slotB, err := BindingCID(keyB, valueB)
	if err != nil {
		t.Fatalf("BindingCID(b) failed: %v", err)
	}
	proved, proof, err := handler.ProveSlot(root, []cid.Cid{slotA, slotB}, 1)
	if err != nil {
		t.Fatalf("ProveSlot failed: %v", err)
	}
	if !proved.Equal(commitment.CellFromCID(slotB)) {
		t.Fatal("ProveSlot returned the wrong binding slot")
	}
	ok, err := handler.VerifySlot(root, 1, proved, proof)
	if err != nil {
		t.Fatalf("VerifySlot failed: %v", err)
	}
	if !ok {
		t.Fatal("VerifySlot returned false")
	}
}

func TestCommitmentProveSlotUsesCallerSuppliedRoot(t *testing.T) {
	scheme := &rootBoundScheme{}
	handler, err := NewCommitment(scheme)
	if err != nil {
		t.Fatalf("NewCommitment failed: %v", err)
	}
	root := testCID(t, "caller-root")
	slot := testCID(t, "slot")
	value, proof, err := handler.ProveSlot(root, []cid.Cid{slot}, 0)
	if err != nil {
		t.Fatalf("ProveSlot failed: %v", err)
	}
	if !scheme.rootBoundCalled || scheme.fallbackCalled {
		t.Fatalf("root-bound=%v fallback=%v; want true, false", scheme.rootBoundCalled, scheme.fallbackCalled)
	}
	if !value.Equal(commitment.CellFromCID(slot)) || len(proof) != 8 {
		t.Fatal("ProveSlot returned an unexpected root-bound opening")
	}
}

func TestCommitmentCommitRejectsInvalidBindings(t *testing.T) {
	handler, err := NewCommitment(testScheme{})
	if err != nil {
		t.Fatalf("NewCommitment failed: %v", err)
	}

	if _, err := handler.Commit(context.Background(), NewViewFromPaths(map[arcset.Path]cid.Cid{
		"": testCID(t, "value"),
	})); err == nil {
		t.Fatal("Commit should reject empty keys")
	}
	if _, err := handler.Commit(context.Background(), NewViewFromPaths(map[arcset.Path]cid.Cid{
		arcset.CanonicalizePath("a"): cid.Undef,
	})); err == nil {
		t.Fatal("Commit should reject undefined values")
	}
}

func TestCommitmentCommitRejectsNonCanonicalIterationOrder(t *testing.T) {
	handler, err := NewCommitment(testScheme{})
	if err != nil {
		t.Fatalf("NewCommitment failed: %v", err)
	}

	if _, err := handler.Commit(context.Background(), orderedView{
		{key: arcset.CanonicalizePath("b"), value: testCID(t, "value-b")},
		{key: arcset.CanonicalizePath("a"), value: testCID(t, "value-a")},
	}); err == nil {
		t.Fatal("Commit should reject non-canonical iteration order")
	}
}

type orderedView []orderedBinding

type orderedBinding struct {
	key   arcset.Path
	value cid.Cid
}

func (v orderedView) Len() int {
	return len(v)
}

func (v orderedView) Get(key arcset.Path) (cid.Cid, bool) {
	for _, binding := range v {
		if binding.key == key {
			return binding.value, true
		}
	}
	return cid.Undef, false
}

func (v orderedView) Iterate() Iterator {
	return &orderedIterator{bindings: v}
}

type orderedIterator struct {
	bindings orderedView
	index    int
}

func (it *orderedIterator) Next() (arcset.Path, cid.Cid, bool) {
	if it.index >= len(it.bindings) {
		return "", cid.Undef, false
	}
	binding := it.bindings[it.index]
	it.index++
	return binding.key, binding.value, true
}

func (it *orderedIterator) Err() error {
	return nil
}

type testScheme struct{}

func (testScheme) MaxValues() int { return 1024 }

func (testScheme) Commit(values []commitment.Cell) (cid.Cid, error) {
	h := sha512.New()
	var lenBuf [8]byte
	for _, value := range values {
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(value)))
		_, _ = h.Write(lenBuf[:])
		_, _ = h.Write(value)
	}
	sum := h.Sum(nil)
	return maltcid.NewMapKZGCid(sum[:maltcid.KZGCommitmentSize])
}

func (s testScheme) Prove(values []commitment.Cell, index uint64) (cid.Cid, commitment.Cell, []byte, error) {
	root, err := s.Commit(values)
	if err != nil {
		return cid.Undef, nil, nil, err
	}
	if index >= uint64(len(values)) {
		return cid.Undef, nil, nil, fmt.Errorf("index %d out of range", index)
	}
	proof := make([]byte, 8)
	binary.BigEndian.PutUint64(proof, index)
	return root, commitment.NewCell(values[index]), proof, nil
}

func (testScheme) BatchProve([]commitment.Cell, []uint64) (cid.Cid, []commitment.Cell, []byte, error) {
	return cid.Undef, nil, nil, fmt.Errorf("not implemented")
}

func (testScheme) VerifyIndex(_ cid.Cid, index uint64, _ commitment.Cell, proof []byte) (bool, error) {
	if len(proof) != 8 {
		return false, fmt.Errorf("proof length = %d, want 8", len(proof))
	}
	return binary.BigEndian.Uint64(proof) == index, nil
}

func (testScheme) BatchVerify(cid.Cid, []uint64, []commitment.Cell, []byte) (bool, error) {
	return false, fmt.Errorf("not implemented")
}

func (testScheme) VerifyProof(cid.Cid, commitment.Cell, []byte) (bool, error) {
	return false, fmt.Errorf("not implemented")
}

func (testScheme) Replace([]commitment.Cell, uint64, commitment.Cell, commitment.Cell) (cid.Cid, error) {
	return cid.Undef, fmt.Errorf("not implemented")
}

type rootBoundScheme struct {
	testScheme
	rootBoundCalled bool
	fallbackCalled  bool
}

func (s *rootBoundScheme) Prove([]commitment.Cell, uint64) (cid.Cid, commitment.Cell, []byte, error) {
	s.fallbackCalled = true
	return cid.Undef, nil, nil, fmt.Errorf("fallback Prove must not be called")
}

func (s *rootBoundScheme) ProveAtRoot(_ cid.Cid, values []commitment.Cell, index uint64) (commitment.Cell, []byte, error) {
	s.rootBoundCalled = true
	if index >= uint64(len(values)) {
		return nil, nil, fmt.Errorf("index %d out of range", index)
	}
	proof := make([]byte, 8)
	binary.BigEndian.PutUint64(proof, index)
	return commitment.NewCell(values[index]), proof, nil
}

func (*rootBoundScheme) BatchProveAtRoot(cid.Cid, []commitment.Cell, []uint64) ([]commitment.Cell, []byte, error) {
	return nil, nil, fmt.Errorf("not implemented")
}

func testCID(t *testing.T, payload string) cid.Cid {
	t.Helper()
	sum, err := mh.Sum([]byte(payload), mh.SHA2_256, -1)
	if err != nil {
		t.Fatalf("mh.Sum failed: %v", err)
	}
	return cid.NewCidV1(cid.Raw, sum)
}

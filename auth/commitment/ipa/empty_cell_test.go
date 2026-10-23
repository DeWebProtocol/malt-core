package ipa_test

import (
	"testing"

	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
)

func TestIPAEmptyCellsMapToZeroAndPreserveOpenings(t *testing.T) {
	scheme, err := ipa.NewCommitterScheme(ipa.ProfileDirect)
	if err != nil {
		t.Fatalf("NewCommitterScheme failed: %v", err)
	}
	verifier, err := ipa.NewVerifierScheme()
	if err != nil {
		t.Fatalf("NewVerifierScheme failed: %v", err)
	}

	fullEmpty := make([]commitment.Cell, ipa.MaxValues)
	implicitPadding, err := scheme.Commit(nil)
	if err != nil {
		t.Fatalf("Commit(nil) failed: %v", err)
	}
	nilCell, err := scheme.Commit([]commitment.Cell{nil})
	if err != nil {
		t.Fatalf("Commit(nil cell) failed: %v", err)
	}
	emptyCell, err := scheme.Commit([]commitment.Cell{commitment.Cell([]byte{})})
	if err != nil {
		t.Fatalf("Commit(empty cell) failed: %v", err)
	}
	fullRoot, err := scheme.Commit(fullEmpty)
	if err != nil {
		t.Fatalf("Commit(full empty) failed: %v", err)
	}
	if !implicitPadding.Equals(nilCell) || !implicitPadding.Equals(emptyCell) || !implicitPadding.Equals(fullRoot) {
		t.Fatalf("empty-cell root differs across implicit and explicit zero padding")
	}

	nonemptyZero := commitment.NewCell([]byte{0})
	nonemptyRoot, err := scheme.Commit([]commitment.Cell{nonemptyZero})
	if err != nil {
		t.Fatalf("Commit(nonempty zero) failed: %v", err)
	}
	if nonemptyRoot.Equals(fullRoot) {
		t.Fatal("nonempty zero-valued cell aliases an empty cell")
	}
	sparseValues := commitment.CloneCells(fullEmpty)
	sparseValues[0] = nonemptyZero
	sparseValues[ipa.MaxValues-1] = commitment.NewCell([]byte("tail"))
	sparseRoot, err := scheme.Commit(sparseValues)
	if err != nil {
		t.Fatalf("Commit(sparse) failed: %v", err)
	}
	sparsePrepared, err := scheme.PrepareOpening(sparseRoot, sparseValues)
	if err != nil {
		t.Fatalf("PrepareOpening(sparse) failed: %v", err)
	}
	for _, index := range []uint64{0, 1, ipa.MaxValues - 1} {
		value, proof, err := sparsePrepared.Open(index)
		if err != nil {
			t.Fatalf("sparse Open(%d) failed: %v", index, err)
		}
		if !value.Equal(sparseValues[index]) {
			t.Fatalf("sparse Open(%d) returned %x, want %x", index, value, sparseValues[index])
		}
		if ok, err := verifier.VerifyIndex(sparseRoot, index, value, proof); err != nil || !ok {
			t.Fatalf("sparse VerifyIndex(%d) = %v, %v; want true, nil", index, ok, err)
		}
	}

	prepared, err := scheme.PrepareOpening(fullRoot, fullEmpty)
	if err != nil {
		t.Fatalf("PrepareOpening failed: %v", err)
	}
	for _, index := range []uint64{0, ipa.MaxValues - 1} {
		value, proof, err := prepared.Open(index)
		if err != nil {
			t.Fatalf("prepared Open(%d) failed: %v", index, err)
		}
		if len(value) != 0 {
			t.Fatalf("prepared Open(%d) returned nonempty value %x", index, value)
		}
		if ok, err := verifier.VerifyIndex(fullRoot, index, value, proof); err != nil || !ok {
			t.Fatalf("VerifyIndex(%d) = %v, %v; want true, nil", index, ok, err)
		}
		if ok, err := verifier.VerifyProof(fullRoot, value, proof); err != nil || !ok {
			t.Fatalf("VerifyProof(%d) = %v, %v; want true, nil", index, ok, err)
		}
		if ok, err := verifier.VerifyIndex(fullRoot, index, nonemptyZero, proof); err != nil || ok {
			t.Fatalf("VerifyIndex(nonempty zero, %d) = %v, %v; want false, nil", index, ok, err)
		}
		wrongIndex := (index + 1) % ipa.MaxValues
		if ok, err := verifier.VerifyIndex(fullRoot, wrongIndex, value, proof); err != nil || ok {
			t.Fatalf("VerifyIndex(wrong index %d) = %v, %v; want false, nil", wrongIndex, ok, err)
		}
	}

	value, proof, err := scheme.Prove(fullRoot, fullEmpty, 1)
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}
	if ok, err := verifier.VerifyIndex(fullRoot, 1, value, proof); err != nil || !ok {
		t.Fatalf("independent VerifyIndex = %v, %v; want true, nil", ok, err)
	}

	indices := []uint64{0, ipa.MaxValues - 1}
	proved, batchProof, err := scheme.BatchProve(fullRoot, fullEmpty, indices)
	if err != nil {
		t.Fatalf("BatchProve failed: %v", err)
	}
	if ok, err := verifier.BatchVerify(fullRoot, indices, proved, batchProof); err != nil || !ok {
		t.Fatalf("independent BatchVerify = %v, %v; want true, nil", ok, err)
	}
	wrongBatch := commitment.CloneCells(proved)
	wrongBatch[0] = nonemptyZero
	if ok, err := verifier.BatchVerify(fullRoot, indices, wrongBatch, batchProof); err != nil || ok {
		t.Fatalf("BatchVerify(nonempty zero) = %v, %v; want false, nil", ok, err)
	}

	replacedRoot, err := scheme.Replace(fullEmpty, 0, nil, nonemptyZero)
	if err != nil {
		t.Fatalf("Replace failed: %v", err)
	}
	wantValues := commitment.CloneCells(fullEmpty)
	wantValues[0] = nonemptyZero
	wantRoot, err := scheme.Commit(wantValues)
	if err != nil {
		t.Fatalf("Commit(replaced) failed: %v", err)
	}
	if !replacedRoot.Equals(wantRoot) || replacedRoot.Equals(fullRoot) {
		t.Fatal("Replace did not preserve the nonempty zero-cell distinction")
	}
}

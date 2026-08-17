package ipa_test

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
)

func TestIPACommitterProfilesAreWireIdentical(t *testing.T) {
	values := []commitment.Cell{
		commitment.NewCell([]byte("slot0")),
		commitment.NewCell([]byte("slot1")),
		commitment.NewCell([]byte("slot2")),
	}
	indices := []uint64{0, 2}
	type output struct {
		root       string
		proof      []byte
		batchProof []byte
	}
	var want output
	for _, profile := range []ipa.CommitterProfile{
		ipa.ProfileDirect,
		ipa.ProfileCompact,
		ipa.ProfileFast,
	} {
		profile := profile
		t.Run(string(profile), func(t *testing.T) {
			scheme, err := ipa.NewCommitterScheme(profile)
			if err != nil {
				t.Fatalf("NewCommitterScheme(%s) failed: %v", profile, err)
			}
			if got, ok := scheme.CommitterProfile(); !ok || got != profile {
				t.Fatalf("CommitterProfile = %q, %v; want %q, true", got, ok, profile)
			}

			root, _, proof, err := scheme.Prove(values, 2)
			if err != nil {
				t.Fatalf("Prove failed: %v", err)
			}
			batchRoot, _, batchProof, err := scheme.BatchProve(values, indices)
			if err != nil {
				t.Fatalf("BatchProve failed: %v", err)
			}
			if !batchRoot.Equals(root) {
				t.Fatalf("batch root %s differs from single root %s", batchRoot, root)
			}
			got := output{root: root.String(), proof: proof, batchProof: batchProof}
			if want.root == "" {
				want = got
				return
			}
			if got.root != want.root {
				t.Fatalf("root = %s, want %s", got.root, want.root)
			}
			if !bytes.Equal(got.proof, want.proof) {
				t.Fatal("single proof differs across committer profiles")
			}
			if !bytes.Equal(got.batchProof, want.batchProof) {
				t.Fatal("batch proof differs across committer profiles")
			}
		})
	}

	verifier, err := ipa.NewVerifierScheme()
	if err != nil {
		t.Fatalf("NewVerifierScheme failed: %v", err)
	}
	if profile, ok := verifier.CommitterProfile(); ok || profile != "" {
		t.Fatalf("verifier CommitterProfile = %q, %v; want empty, false", profile, ok)
	}
	if _, err := verifier.Commit(values); err == nil || !strings.Contains(err.Error(), "verification-only") {
		t.Fatalf("verifier Commit error = %v; want verification-only failure", err)
	}
	if _, err := ipa.NewCommitterScheme("unknown"); err == nil {
		t.Fatal("NewCommitterScheme accepted an unknown profile")
	}
}

func TestIPAParameterFingerprint(t *testing.T) {
	const expected = "3799df0a77d1843b13a3a08744165180a12e1cd2dca529bee64ad691ac63adaf"
	if got := ipa.ParameterSHA256(); got != expected {
		t.Fatalf("ParameterSHA256 = %s, want %s", got, expected)
	}
}

func TestIPAProveIsStateless(t *testing.T) {
	scheme, err := ipa.NewScheme()
	if err != nil {
		t.Fatalf("NewScheme failed: %v", err)
	}

	values := []commitment.Cell{
		commitment.NewCell([]byte("slot0")),
		commitment.NewCell([]byte("slot1")),
		commitment.NewCell([]byte("slot2")),
	}
	root, err := scheme.Commit(values)
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	provedRoot, value, proof, err := scheme.Prove(values, 2)
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}
	if !provedRoot.Equals(root) {
		t.Fatalf("unexpected recomputed root %s", provedRoot)
	}
	if !value.Equal(values[2]) {
		t.Fatalf("unexpected value %x", value)
	}

	ok, err := scheme.VerifyIndex(root, 2, values[2], proof)
	if err != nil {
		t.Fatalf("VerifyIndex failed: %v", err)
	}
	if !ok {
		t.Fatal("expected proof to verify")
	}

	wrong := commitment.NewCell([]byte("wrong"))
	ok, err = scheme.VerifyIndex(root, 2, wrong, proof)
	if err != nil {
		t.Fatalf("VerifyIndex(wrong) failed: %v", err)
	}
	if ok {
		t.Fatal("expected wrong value verification to fail")
	}

	_, value0, proof0, err := scheme.Prove(values, 0)
	if err != nil {
		t.Fatalf("Prove(0) failed: %v", err)
	}
	if !value0.Equal(values[0]) {
		t.Fatalf("unexpected value at index 0: %x", value0)
	}

	ok, err = scheme.VerifyIndex(root, 0, values[0], proof0)
	if err != nil {
		t.Fatalf("VerifyIndex(0) failed: %v", err)
	}
	if !ok {
		t.Fatal("expected index 0 proof to verify")
	}

	_, value1, proof1, err := scheme.Prove(values, 1)
	if err != nil {
		t.Fatalf("Prove(1) failed: %v", err)
	}
	if !value1.Equal(values[1]) {
		t.Fatalf("unexpected value at index 1: %x", value1)
	}

	ok, err = scheme.VerifyIndex(root, 1, values[1], proof1)
	if err != nil {
		t.Fatalf("VerifyIndex(1) failed: %v", err)
	}
	if !ok {
		t.Fatal("expected index 1 proof to verify")
	}

	ok, err = scheme.VerifyProof(root, values[2], proof)
	if err != nil {
		t.Fatalf("VerifyProof failed: %v", err)
	}
	if !ok {
		t.Fatal("expected VerifyProof to verify")
	}
}

func TestIPAProveAtRootRejectsInconsistentMaterialization(t *testing.T) {
	scheme, err := ipa.NewScheme()
	if err != nil {
		t.Fatalf("NewScheme failed: %v", err)
	}
	values := []commitment.Cell{
		commitment.NewCell([]byte("slot0")),
		commitment.NewCell([]byte("slot1")),
	}
	root, err := scheme.Commit(values)
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}
	value, proof, err := scheme.ProveAtRoot(root, values, 1)
	if err != nil {
		t.Fatalf("ProveAtRoot failed: %v", err)
	}
	if !value.Equal(values[1]) {
		t.Fatalf("unexpected value %x", value)
	}
	if ok, err := scheme.VerifyIndex(root, 1, value, proof); err != nil || !ok {
		t.Fatalf("VerifyIndex = %v, %v; want true, nil", ok, err)
	}

	inconsistent := commitment.CloneCells(values)
	inconsistent[0] = commitment.NewCell([]byte("different slot0"))
	if _, _, err := scheme.ProveAtRoot(root, inconsistent, 1); err == nil {
		t.Fatal("ProveAtRoot accepted materialization inconsistent with root")
	}
	if _, _, err := scheme.ProveAtRoot(root, make([]commitment.Cell, ipa.MaxValues+1), 0); err == nil {
		t.Fatal("ProveAtRoot accepted an oversized materialization")
	}
}

func TestIPAPreparedOpeningBindsRootAndClonesWitness(t *testing.T) {
	scheme, err := ipa.NewScheme()
	if err != nil {
		t.Fatalf("NewScheme failed: %v", err)
	}
	values := []commitment.Cell{
		commitment.NewCell([]byte("slot0")),
		commitment.NewCell([]byte("slot1")),
	}
	wantRoot, err := scheme.Commit(values)
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}
	prepared, err := scheme.PrepareOpening(values)
	if err != nil {
		t.Fatalf("PrepareOpening failed: %v", err)
	}
	if !prepared.Root().Equals(wantRoot) {
		t.Fatalf("prepared root %s, want %s", prepared.Root(), wantRoot)
	}

	values[1] = commitment.NewCell([]byte("attacker replacement"))
	value, proof, err := prepared.Open(1)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if value.Equal(values[1]) {
		t.Fatal("prepared opening retained caller-owned mutable witness")
	}
	ok, err := scheme.VerifyIndex(prepared.Root(), 1, value, proof)
	if err != nil || !ok {
		t.Fatalf("VerifyIndex = %v, %v; want true, nil", ok, err)
	}
	otherRoot, err := scheme.Commit(values)
	if err != nil {
		t.Fatalf("Commit(other) failed: %v", err)
	}
	if ok, err := scheme.VerifyIndex(otherRoot, 1, value, proof); err == nil && ok {
		t.Fatal("prepared proof verified against a mismatched root")
	}
}

func TestIPAReplaceIsStateless(t *testing.T) {
	scheme, err := ipa.NewScheme()
	if err != nil {
		t.Fatalf("NewScheme failed: %v", err)
	}

	values := []commitment.Cell{
		commitment.NewCell([]byte("slot0")),
		commitment.NewCell([]byte("slot1")),
	}
	root, err := scheme.Commit(values)
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	newValue := commitment.NewCell([]byte("slot1-new"))
	newRoot, err := scheme.Replace(values, 1, values[1], newValue)
	if err != nil {
		t.Fatalf("Replace failed: %v", err)
	}
	if newRoot.Equals(root) {
		t.Fatal("expected replacement to change root")
	}

	updatedValues := []commitment.Cell{values[0], newValue}
	recomputedRoot, err := scheme.Commit(updatedValues)
	if err != nil {
		t.Fatalf("Commit(updated) failed: %v", err)
	}
	if !recomputedRoot.Equals(newRoot) {
		t.Fatalf("updated root mismatch: %s != %s", recomputedRoot, newRoot)
	}

	provedRoot, value, proof, err := scheme.Prove(updatedValues, 1)
	if err != nil {
		t.Fatalf("Prove on updated values failed: %v", err)
	}
	if !provedRoot.Equals(newRoot) {
		t.Fatalf("unexpected updated root %s", provedRoot)
	}
	if !value.Equal(newValue) {
		t.Fatalf("unexpected updated value %x", value)
	}

	ok, err := scheme.VerifyIndex(newRoot, 1, newValue, proof)
	if err != nil {
		t.Fatalf("VerifyIndex on updated root failed: %v", err)
	}
	if !ok {
		t.Fatal("expected updated proof to verify")
	}
}

func TestIPABatchProveIsStateless(t *testing.T) {
	scheme, err := ipa.NewScheme()
	if err != nil {
		t.Fatalf("NewScheme failed: %v", err)
	}

	values := []commitment.Cell{
		commitment.NewCell([]byte("slot0")),
		commitment.NewCell([]byte("slot1")),
		commitment.NewCell([]byte("slot2")),
	}
	root, err := scheme.Commit(values)
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	indices := []uint64{0, 2}
	provedRoot, proved, proof, err := scheme.BatchProve(values, indices)
	if err != nil {
		t.Fatalf("BatchProve failed: %v", err)
	}
	if !provedRoot.Equals(root) {
		t.Fatalf("unexpected batch root %s", provedRoot)
	}
	if len(proved) != len(indices) {
		t.Fatalf("unexpected proved length: %d", len(proved))
	}
	if !proved[0].Equal(values[0]) || !proved[1].Equal(values[2]) {
		t.Fatalf("unexpected proved values: %x %x", proved[0], proved[1])
	}

	ok, err := scheme.BatchVerify(root, indices, []commitment.Cell{values[0], values[2]}, proof)
	if err != nil {
		t.Fatalf("BatchVerify failed: %v", err)
	}
	if !ok {
		t.Fatal("expected batch proof to verify")
	}

	ok, err = scheme.BatchVerify(root, indices, []commitment.Cell{values[0], commitment.NewCell([]byte("wrong"))}, proof)
	if err != nil {
		t.Fatalf("BatchVerify(wrong) failed: %v", err)
	}
	if ok {
		t.Fatal("expected wrong batch value verification to fail")
	}

	rootBoundValues, rootBoundProof, err := scheme.BatchProveAtRoot(root, values, indices)
	if err != nil {
		t.Fatalf("BatchProveAtRoot failed: %v", err)
	}
	if ok, err := scheme.BatchVerify(root, indices, rootBoundValues, rootBoundProof); err != nil || !ok {
		t.Fatalf("root-bound BatchVerify = %v, %v; want true, nil", ok, err)
	}
	inconsistent := commitment.CloneCells(values)
	inconsistent[1] = commitment.NewCell([]byte("different slot1"))
	if _, _, err := scheme.BatchProveAtRoot(root, inconsistent, indices); err == nil {
		t.Fatal("BatchProveAtRoot accepted materialization inconsistent with root")
	}
}

func TestIPABatchOperationsRejectOversizedRequests(t *testing.T) {
	scheme, err := ipa.NewScheme()
	if err != nil {
		t.Fatalf("NewScheme failed: %v", err)
	}
	values := []commitment.Cell{commitment.NewCell([]byte("slot0"))}
	root, err := scheme.Commit(values)
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}
	indices := make([]uint64, ipa.MaxValues+1)
	proved := make([]commitment.Cell, len(indices))
	for i := range proved {
		proved[i] = values[0]
	}

	if _, _, _, err := scheme.BatchProve(values, indices); err == nil {
		t.Fatal("BatchProve accepted too many indices")
	}
	if _, _, err := scheme.BatchProveAtRoot(root, values, indices); err == nil {
		t.Fatal("BatchProveAtRoot accepted too many indices")
	}
	if ok, err := scheme.BatchVerify(root, indices, proved, nil); err == nil || ok {
		t.Fatalf("BatchVerify(too many indices) = %v, %v; want false, error", ok, err)
	}
}

func TestIPAVerifyRejectsOverflowingRoundCount(t *testing.T) {
	scheme, err := ipa.NewScheme()
	if err != nil {
		t.Fatalf("NewScheme failed: %v", err)
	}
	values := []commitment.Cell{commitment.NewCell([]byte("slot0"))}
	root, err := scheme.Commit(values)
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}
	proof := make([]byte, ipa.ProofSize)
	binary.BigEndian.PutUint32(proof[:4], uint32(1)<<31)
	if ok, err := scheme.VerifyIndex(root, 0, values[0], proof); err == nil || ok {
		t.Fatalf("VerifyIndex(overflowing round count) = %v, %v; want false, error", ok, err)
	}
	if ok, err := scheme.VerifyProof(root, values[0], proof); err == nil || ok {
		t.Fatalf("VerifyProof(overflowing round count) = %v, %v; want false, error", ok, err)
	}
}

func TestIPAVerifyRejectsOutOfRangeStableIndex(t *testing.T) {
	scheme, err := ipa.NewScheme()
	if err != nil {
		t.Fatalf("NewScheme failed: %v", err)
	}
	values := []commitment.Cell{commitment.NewCell([]byte("slot0"))}
	root, value, proof, err := scheme.Prove(values, 0)
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}
	const hostileIndex = uint64(1) << 31
	if ok, err := scheme.VerifyIndex(root, hostileIndex, value, proof); err == nil || ok {
		t.Fatalf("VerifyIndex(out-of-range index) = %v, %v; want false, error", ok, err)
	}

	hostileProof := append([]byte(nil), proof...)
	binary.BigEndian.PutUint32(hostileProof[len(hostileProof)-4:], uint32(hostileIndex))
	if ok, err := scheme.VerifyProof(root, value, hostileProof); err == nil || ok {
		t.Fatalf("VerifyProof(out-of-range index) = %v, %v; want false, error", ok, err)
	}
}

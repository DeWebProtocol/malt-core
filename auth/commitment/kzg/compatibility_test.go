package kzg_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"math/bits"
	"testing"

	blsfr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	gokzg4844 "github.com/crate-crypto/go-kzg-4844"
	"github.com/dewebprotocol/malt/auth/commitment"
	"github.com/dewebprotocol/malt/auth/commitment/kzg"
	"github.com/dewebprotocol/malt/wire/maltcid"
)

var compatibilityScalarModulus, _ = new(big.Int).SetString(
	"73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
	16,
)

func TestKZGPreprocessedWriterMatchesGoKZG(t *testing.T) {
	legacy, err := gokzg4844.NewContext4096Secure()
	if err != nil {
		t.Fatalf("NewContext4096Secure: %v", err)
	}
	writer, err := kzg.NewScheme()
	if err != nil {
		t.Fatalf("NewScheme: %v", err)
	}
	verifier, err := kzg.NewVerifierScheme()
	if err != nil {
		t.Fatalf("NewVerifierScheme: %v", err)
	}

	values := compatibilityValues()
	blob := legacyBlob(values)
	legacyCommitment, err := legacy.BlobToKZGCommitment(blob, 1)
	if err != nil {
		t.Fatalf("legacy BlobToKZGCommitment: %v", err)
	}
	prepared, err := writer.PrepareOpening(values)
	if err != nil {
		t.Fatalf("PrepareOpening: %v", err)
	}
	commitmentBytes, err := maltcid.ExtractCommitment(prepared.Root())
	if err != nil {
		t.Fatalf("ExtractCommitment: %v", err)
	}
	if !bytes.Equal(commitmentBytes, legacyCommitment[:]) {
		t.Fatalf("commitment mismatch\nnew:    %x\nlegacy: %x", commitmentBytes, legacyCommitment)
	}

	domain := legacyDomainPoints(t)
	for _, index := range []uint64{0, 1, 2, 3, 0x155, 0x555, 0x800, 0xaaa, kzg.MaxValues - 2, kzg.MaxValues - 1} {
		value, proof, err := prepared.Open(index)
		if err != nil {
			t.Fatalf("Open(%d): %v", index, err)
		}
		legacyProof, legacyClaimed, err := legacy.ComputeKZGProof(blob, domain[index], 1)
		if err != nil {
			t.Fatalf("legacy ComputeKZGProof(%d): %v", index, err)
		}
		if !bytes.Equal(proof[:48], legacyProof[:]) {
			t.Fatalf("proof mismatch at %d\nnew:    %x\nlegacy: %x", index, proof[:48], legacyProof)
		}
		if !bytes.Equal(proof[48:80], legacyClaimed[:]) {
			t.Fatalf("claimed scalar mismatch at %d\nnew:    %x\nlegacy: %x", index, proof[48:80], legacyClaimed)
		}
		if err := legacy.VerifyKZGProof(
			legacyCommitment,
			domain[index],
			legacyClaimed,
			gokzg4844.KZGProof(*(*[48]byte)(proof[:48])),
		); err != nil {
			t.Fatalf("legacy verifier rejected new proof at %d: %v", index, err)
		}
		legacyEncoded := encodeLegacyProof(legacyProof, legacyClaimed, index)
		ok, err := verifier.VerifyIndex(prepared.Root(), index, value, legacyEncoded)
		if err != nil || !ok {
			t.Fatalf("new verifier rejected legacy proof at %d: %v, %v", index, ok, err)
		}
	}
}

func compatibilityValues() []commitment.Cell {
	values := make([]commitment.Cell, kzg.MaxValues)
	for i := range values {
		value := make([]byte, len("malt-kzg-compat-slot:")+4)
		copy(value, "malt-kzg-compat-slot:")
		binary.BigEndian.PutUint32(value[len(value)-4:], uint32(i))
		values[i] = commitment.NewCell(value)
	}
	return values
}

func TestKZGBatchEncodingMatchesLegacyPrimitiveProofs(t *testing.T) {
	legacy, err := gokzg4844.NewContext4096Secure()
	if err != nil {
		t.Fatalf("NewContext4096Secure: %v", err)
	}
	writer, err := kzg.NewScheme()
	if err != nil {
		t.Fatalf("NewScheme: %v", err)
	}
	values := []commitment.Cell{
		commitment.NewCell([]byte("zero")),
		commitment.NewCell([]byte("one")),
		commitment.NewCell([]byte("two")),
	}
	indices := []uint64{0, 2}
	root, proved, batchProof, err := writer.BatchProve(values, indices)
	if err != nil {
		t.Fatalf("BatchProve: %v", err)
	}
	blob := legacyBlob(values)
	domain := legacyDomainPoints(t)
	want := make([]byte, 4, 4+len(indices)*kzg.ProofSize)
	want[3] = byte(len(indices))
	for _, index := range indices {
		proof, claimed, err := legacy.ComputeKZGProof(blob, domain[index], 1)
		if err != nil {
			t.Fatalf("legacy ComputeKZGProof(%d): %v", index, err)
		}
		want = append(want, encodeLegacyProof(proof, claimed, index)...)
	}
	if !bytes.Equal(batchProof, want) {
		t.Fatalf("batch proof mismatch\nnew:    %x\nlegacy: %x", batchProof, want)
	}
	if ok, err := writer.BatchVerify(root, indices, proved, batchProof); err != nil || !ok {
		t.Fatalf("BatchVerify = %v, %v; want true, nil", ok, err)
	}
}

func legacyBlob(values []commitment.Cell) *gokzg4844.Blob {
	blob := new(gokzg4844.Blob)
	for i, value := range values {
		hash := sha256.Sum256(value)
		fieldValue := new(big.Int).SetBytes(hash[:])
		fieldValue.Mod(fieldValue, compatibilityScalarModulus)
		encoded := fieldValue.FillBytes(make([]byte, gokzg4844.SerializedScalarSize))
		copy(blob[i*gokzg4844.SerializedScalarSize:], encoded)
	}
	return blob
}

func legacyDomainPoints(t *testing.T) []gokzg4844.Scalar {
	t.Helper()
	var rootOfUnity blsfr.Element
	if _, err := rootOfUnity.SetString("10238227357739495823651030575849232062558860180284477541189508159991286009131"); err != nil {
		t.Fatal(err)
	}
	var generator blsfr.Element
	generator.Exp(rootOfUnity, new(big.Int).SetUint64(1<<(32-12)))
	roots := make([]blsfr.Element, kzg.MaxValues)
	current := blsfr.One()
	for i := range roots {
		roots[i] = current
		current.Mul(&current, &generator)
	}
	for i := range roots {
		j := int(bits.Reverse(uint(i)) >> (bits.UintSize - 12))
		if j > i {
			roots[i], roots[j] = roots[j], roots[i]
		}
	}
	points := make([]gokzg4844.Scalar, len(roots))
	for i := range roots {
		points[i] = gokzg4844.SerializeScalar(roots[i])
	}
	return points
}

func encodeLegacyProof(proof gokzg4844.KZGProof, claimed gokzg4844.Scalar, index uint64) []byte {
	encoded := make([]byte, 0, kzg.ProofSize)
	encoded = append(encoded, proof[:]...)
	encoded = append(encoded, claimed[:]...)
	encoded = append(encoded, byte(index>>24), byte(index>>16), byte(index>>8), byte(index))
	return encoded
}

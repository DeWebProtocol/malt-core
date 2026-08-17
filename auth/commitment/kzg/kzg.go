// Package kzg provides a KZG polynomial commitment backend.
package kzg

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"

	gokzg4844 "github.com/crate-crypto/go-kzg-4844"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

// bls12381ScalarMod is the BLS12-381 scalar field modulus.
var bls12381ScalarMod, _ = new(big.Int).SetString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)

const (
	// MaxValues is the maximum number of values per commitment (KZG constraint).
	MaxValues = 4096
	// ProofSize is the size of a primitive KZG index proof in bytes.
	ProofSize = 84
	// MaxCacheEntries is the maximum number of cached commitments.
	// When exceeded, the oldest entries are evicted.
	MaxCacheEntries = 1024
)

// VerifierScheme is the verification-only KZG backend. It deliberately does
// not retain or link the 4096-point writer commitment key.
type VerifierScheme struct {
	openingKey *kzgOpeningKey
	domain     *kzgDomain
}

// Scheme implements the full KZG index commitment backend.
type Scheme struct {
	*VerifierScheme
	writerKey *kzgWriterKey
}

var _ commitment.IndexOpener = (*Scheme)(nil)

// NewScheme creates a new KZG commitment scheme.
func NewScheme() (*Scheme, error) {
	verifier, err := NewVerifierScheme()
	if err != nil {
		return nil, err
	}
	writerKey, err := loadKZGWriterKey()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize KZG writer key: %w", err)
	}
	return &Scheme{VerifierScheme: verifier, writerKey: writerKey}, nil
}

// NewVerifierScheme creates a KZG verifier without loading the 4096-point
// writer key. This is the constructor for portable and browser verifiers.
func NewVerifierScheme() (*VerifierScheme, error) {
	openingKey, err := loadKZGOpeningKey()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize KZG opening key: %w", err)
	}
	domain, err := loadKZGDomain()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize KZG domain: %w", err)
	}
	return &VerifierScheme{openingKey: openingKey, domain: domain}, nil
}

// MaxValues returns the maximum number of authenticated slots.
func (s *VerifierScheme) MaxValues() int {
	return MaxValues
}

// Commit commits a stable indexed cell vector.
func (s *Scheme) Commit(values []commitment.Cell) (cid.Cid, error) {
	return s.commitValues(values)
}

// Prove proves the value at a stable index.
func (s *Scheme) Prove(values []commitment.Cell, index uint64) (cid.Cid, commitment.Cell, []byte, error) {
	comm, err := s.commitValues(values)
	if err != nil {
		return cid.Undef, nil, nil, err
	}
	if index >= uint64(len(values)) {
		return cid.Undef, nil, nil, fmt.Errorf("index %d out of range", index)
	}
	value, proof, err := s.proveValuesIndex(values, index)
	return comm, value, proof, err
}

// ProveAtRoot opens values against a caller-supplied root without recomputing
// the KZG commitment. The generated proof is verified before it is returned so
// inconsistent client materialization fails closed.
func (s *Scheme) ProveAtRoot(root cid.Cid, values []commitment.Cell, index uint64) (commitment.Cell, []byte, error) {
	if _, err := maltcid.ExtractCommitment(root); err != nil {
		return nil, nil, fmt.Errorf("invalid proof root: %w", err)
	}
	if maltcid.BackendKindOf(root) != maltcid.BackendKindKZG {
		return nil, nil, fmt.Errorf("proof root does not use the KZG backend")
	}
	if len(values) > MaxValues {
		return nil, nil, fmt.Errorf("too many values: %d > %d", len(values), MaxValues)
	}
	if index >= uint64(len(values)) {
		return nil, nil, fmt.Errorf("index %d out of range", index)
	}
	value, proof, err := s.proveValuesIndex(values, index)
	if err != nil {
		return nil, nil, err
	}
	ok, err := s.VerifyIndex(root, index, value, append([]byte(nil), proof...))
	if err != nil {
		return nil, nil, fmt.Errorf("verify root-bound KZG proof: %w", err)
	}
	if !ok {
		return nil, nil, commitment.ErrInvalidCommitment
	}
	return value, proof, nil
}

type opening struct {
	scheme *Scheme
	root   cid.Cid
	values []commitment.Cell
}

// PrepareOpening computes a commitment once and returns an opaque witness
// whose Open method never calls BlobToKZGCommitment.
func (s *Scheme) PrepareOpening(values []commitment.Cell) (commitment.IndexOpening, error) {
	root, err := s.commitValues(values)
	if err != nil {
		return nil, err
	}
	return &opening{scheme: s, root: root, values: commitment.CloneCells(values)}, nil
}

func (o *opening) Root() cid.Cid { return o.root }

func (o *opening) Open(index uint64) (commitment.Cell, []byte, error) {
	if index >= uint64(len(o.values)) {
		return nil, nil, fmt.Errorf("index %d out of range", index)
	}
	return o.scheme.proveValuesIndex(o.values, index)
}

func (s *Scheme) proveValuesIndex(values []commitment.Cell, index uint64) (commitment.Cell, []byte, error) {
	polynomial, err := polynomialFromValues(values)
	if err != nil {
		return nil, nil, err
	}
	proof, claimedValue, err := provePolynomialAtIndex(s.writerKey, s.domain, polynomial, index)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute proof: %w", err)
	}
	return commitment.NewCell(values[index]), serializeProof(proof, claimedValue, index), nil
}

// BatchProve currently concatenates single-index KZG proofs because the
// current go-kzg-4844 dependency does not expose batch opening generation.
// TODO: replace this looped encoding with a real KZG multiproof when the
// backend supports batch opening generation for our index-commitment setting.
func (s *Scheme) BatchProve(values []commitment.Cell, indices []uint64) (cid.Cid, []commitment.Cell, []byte, error) {
	if err := validateBatchOpening(values, indices); err != nil {
		return cid.Undef, nil, nil, err
	}
	comm, err := s.commitValues(values)
	if err != nil {
		return cid.Undef, nil, nil, err
	}

	proved := make([]commitment.Cell, len(indices))
	proofs := make([][]byte, len(indices))
	for i, index := range indices {
		value, proof, err := s.proveValuesIndex(values, index)
		if err != nil {
			return cid.Undef, nil, nil, err
		}
		proved[i] = value
		proofs[i] = proof
	}
	return comm, proved, serializeBatchProof(proofs), nil
}

// BatchProveAtRoot opens values against a caller-supplied root without
// recomputing the KZG commitment.
func (s *Scheme) BatchProveAtRoot(root cid.Cid, values []commitment.Cell, indices []uint64) ([]commitment.Cell, []byte, error) {
	if _, err := maltcid.ExtractCommitment(root); err != nil {
		return nil, nil, fmt.Errorf("invalid proof root: %w", err)
	}
	if maltcid.BackendKindOf(root) != maltcid.BackendKindKZG {
		return nil, nil, fmt.Errorf("proof root does not use the KZG backend")
	}
	if err := validateBatchOpening(values, indices); err != nil {
		return nil, nil, err
	}

	proved := make([]commitment.Cell, len(indices))
	proofs := make([][]byte, len(indices))
	for i, index := range indices {
		value, proof, err := s.proveValuesIndex(values, index)
		if err != nil {
			return nil, nil, err
		}
		proved[i] = value
		proofs[i] = proof
	}
	proof := serializeBatchProof(proofs)
	ok, err := s.BatchVerify(root, indices, proved, append([]byte(nil), proof...))
	if err != nil {
		return nil, nil, fmt.Errorf("verify root-bound KZG batch proof: %w", err)
	}
	if !ok {
		return nil, nil, commitment.ErrInvalidCommitment
	}
	return proved, proof, nil
}

// VerifyIndex verifies a proof for a stable index without cache state.
func (s *VerifierScheme) VerifyIndex(comm cid.Cid, index uint64, value commitment.Cell, proof []byte) (bool, error) {
	if index >= uint64(len(s.domain.roots)) {
		return false, fmt.Errorf("index %d exceeds max %d", index, len(s.domain.roots)-1)
	}
	kzgProof, claimedValue, proofIndex, err := deserializeProof(proof)
	if err != nil {
		return false, err
	}
	if proofIndex >= uint64(len(s.domain.roots)) {
		return false, fmt.Errorf("proof index %d exceeds max %d", proofIndex, len(s.domain.roots)-1)
	}
	if proofIndex != index {
		return false, nil
	}
	expected := cellToKZGScalar(value)
	if claimedValue != expected {
		return false, nil
	}

	commBytes, err := maltcid.ExtractCommitment(comm)
	if err != nil {
		return false, fmt.Errorf("failed to extract commitment: %w", err)
	}
	var kzgComm gokzg4844.KZGCommitment
	copy(kzgComm[:], commBytes)

	if err := verifyKZGOpening(s.openingKey, kzgComm, s.domain.roots[index], claimedValue, kzgProof); err != nil {
		return false, fmt.Errorf("KZG proof verification failed: %w", err)
	}
	return true, nil
}

// BatchVerify currently replays single-index KZG verification because the
// current go-kzg-4844 dependency does not expose batch opening generation.
// TODO: replace this looped verification path once BatchProve emits a real
// KZG multiproof for our index-commitment setting.
func (s *VerifierScheme) BatchVerify(comm cid.Cid, indices []uint64, values []commitment.Cell, proof []byte) (bool, error) {
	if err := validateBatchVerification(indices, values); err != nil {
		return false, err
	}

	proofs, err := deserializeBatchProof(proof)
	if err != nil {
		return false, err
	}
	if len(proofs) != len(indices) {
		return false, fmt.Errorf("batch proof count mismatch: %d != %d", len(proofs), len(indices))
	}

	for i := range indices {
		ok, err := s.VerifyIndex(comm, indices[i], values[i], proofs[i])
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
	}
	return true, nil
}

func validateBatchOpening(values []commitment.Cell, indices []uint64) error {
	if len(values) > MaxValues {
		return fmt.Errorf("too many values: %d > %d", len(values), MaxValues)
	}
	if len(indices) == 0 {
		return fmt.Errorf("indices must not be empty")
	}
	if len(indices) > MaxValues {
		return fmt.Errorf("too many indices: %d > %d", len(indices), MaxValues)
	}
	for _, index := range indices {
		if index >= uint64(len(values)) {
			return fmt.Errorf("index %d out of range", index)
		}
	}
	return nil
}

func validateBatchVerification(indices []uint64, values []commitment.Cell) error {
	if len(indices) == 0 {
		return fmt.Errorf("indices must not be empty")
	}
	if len(indices) > MaxValues {
		return fmt.Errorf("too many indices: %d > %d", len(indices), MaxValues)
	}
	if len(indices) != len(values) {
		return fmt.Errorf("indices/value length mismatch: %d != %d", len(indices), len(values))
	}
	for _, index := range indices {
		if index >= MaxValues {
			return fmt.Errorf("index %d exceeds max %d", index, MaxValues-1)
		}
	}
	return nil
}

// VerifyProof verifies a proof carrying its own index metadata.
func (s *VerifierScheme) VerifyProof(comm cid.Cid, value commitment.Cell, proof []byte) (bool, error) {
	_, _, index, err := deserializeProof(proof)
	if err != nil {
		return false, err
	}
	return s.VerifyIndex(comm, index, value, proof)
}

// Replace performs an index-stable replacement.
func (s *Scheme) Replace(values []commitment.Cell, index uint64, oldValue, newValue commitment.Cell) (cid.Cid, error) {
	if index >= uint64(len(values)) {
		return cid.Cid{}, fmt.Errorf("index %d out of range", index)
	}
	if !values[index].Equal(oldValue) {
		return cid.Cid{}, fmt.Errorf("old value mismatch at index %d", index)
	}

	nextValues := commitment.CloneCells(values)
	nextValues[index] = commitment.NewCell(newValue)
	return s.commitValues(nextValues)
}

func cellToKZGScalar(value commitment.Cell) gokzg4844.Scalar {
	var scalar gokzg4844.Scalar
	hash := sha256.Sum256(value)

	fieldValue := new(big.Int).SetBytes(hash[:])
	fieldValue.Mod(fieldValue, bls12381ScalarMod)

	result := fieldValue.FillBytes(make([]byte, 32))
	copy(scalar[:], result)

	return scalar
}

func (s *Scheme) commitValues(values []commitment.Cell) (cid.Cid, error) {
	if len(values) > MaxValues {
		return cid.Cid{}, fmt.Errorf("too many values: %d > %d", len(values), MaxValues)
	}

	polynomial, err := polynomialFromValues(values)
	if err != nil {
		return cid.Cid{}, err
	}
	comm, err := commitPolynomial(s.writerKey, polynomial)
	if err != nil {
		return cid.Cid{}, fmt.Errorf("failed to commit: %w", err)
	}

	commBytes := comm[:]
	return maltcid.NewKZGCid(commBytes)
}

func serializeProof(proof gokzg4844.KZGProof, claimedValue gokzg4844.Scalar, index uint64) []byte {
	proofBytes := make([]byte, 0, ProofSize)
	proofBytes = append(proofBytes, proof[:]...)
	proofBytes = append(proofBytes, claimedValue[:]...)
	proofBytes = append(proofBytes, byte(index>>24), byte(index>>16), byte(index>>8), byte(index))
	return proofBytes
}

func deserializeProof(data []byte) (gokzg4844.KZGProof, gokzg4844.Scalar, uint64, error) {
	if len(data) != ProofSize {
		return gokzg4844.KZGProof{}, gokzg4844.Scalar{}, 0, fmt.Errorf("proof has wrong size: expected %d, got %d", ProofSize, len(data))
	}
	var proof gokzg4844.KZGProof
	var claimed gokzg4844.Scalar
	copy(proof[:], data[:48])
	copy(claimed[:], data[48:80])
	index := uint64(data[80])<<24 | uint64(data[81])<<16 | uint64(data[82])<<8 | uint64(data[83])
	return proof, claimed, index, nil
}

func serializeBatchProof(proofs [][]byte) []byte {
	buf := make([]byte, 4+len(proofs)*ProofSize)
	binary.BigEndian.PutUint32(buf[:4], uint32(len(proofs)))
	offset := 4
	for _, proof := range proofs {
		copy(buf[offset:offset+ProofSize], proof)
		offset += ProofSize
	}
	return buf
}

func deserializeBatchProof(data []byte) ([][]byte, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("batch proof too short: %d", len(data))
	}

	rawCount := binary.BigEndian.Uint32(data[:4])
	if rawCount > uint32(MaxValues) {
		return nil, fmt.Errorf("batch proof count exceeds max: %d > %d", rawCount, MaxValues)
	}
	count := int(rawCount)
	expectedSize := 4 + count*ProofSize
	if len(data) != expectedSize {
		return nil, fmt.Errorf("batch proof has wrong size: expected %d, got %d", expectedSize, len(data))
	}

	proofs := make([][]byte, count)
	offset := 4
	for i := 0; i < count; i++ {
		proofs[i] = append([]byte(nil), data[offset:offset+ProofSize]...)
		offset += ProofSize
	}
	return proofs, nil
}

// Ensure Scheme implements commitment.IndexCommitment.
var _ commitment.IndexCommitment = (*Scheme)(nil)
var _ commitment.IndexVerifier = (*VerifierScheme)(nil)
var _ commitment.IndexVerifier = (*Scheme)(nil)
var _ commitment.IndexProver = (*Scheme)(nil)
var _ commitment.IndexRootProver = (*Scheme)(nil)

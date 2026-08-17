// Package ipa provides an IPA (Inner Product Argument) commitment backend.
package ipa

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/dewebprotocol/malt-core/auth/commitment"
	multiproof "github.com/dewebprotocol/malt-core/internal/third_party/goipa"
	"github.com/dewebprotocol/malt-core/internal/third_party/goipa/bandersnatch/fr"
	"github.com/dewebprotocol/malt-core/internal/third_party/goipa/banderwagon"
	"github.com/dewebprotocol/malt-core/internal/third_party/goipa/common"
	ipa "github.com/dewebprotocol/malt-core/internal/third_party/goipa/ipa"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

const (
	// MaxValues is the maximum number of values per commitment.
	MaxValues   = 256
	proofRounds = 8
	// ProofSize is the size of a primitive IPA index proof in bytes.
	// For 256 elements: numRounds=8, size=4 + 8*32(L) + 8*32(R) + 32(A_scalar) + 4(index) = 552
	ProofSize = 552
	// MaxCacheEntries is the maximum number of cached commitments.
	// When exceeded, the oldest entries are evicted.
	MaxCacheEntries = 1024
)

// ParameterSetID identifies the fixed IPA SRS serialization hashed by
// ParameterSHA256.
const ParameterSetID = "malt.ipa-parameters/v1"

const (
	singleTranscriptLabel = "malt-ipa"
	batchTranscriptLabel  = "malt-ipa-batch"
)

// Scheme implements an IPA-based index commitment backend.
type Scheme struct {
	ipaConfig    *ipa.IPAConfig
	profile      CommitterProfile
	verifierOnly bool
}

var _ commitment.IndexOpener = (*Scheme)(nil)

// CommitterProfile selects an IPA fixed-base MSM memory/performance tradeoff.
// Profiles never change the SRS, commitment bytes, proof bytes, or typed CID.
type CommitterProfile string

const (
	// ProfileDirect retains no fixed-base table and performs a generic MSM for
	// every commitment.
	ProfileDirect CommitterProfile = "direct"
	// ProfileCompact retains a uniform 4-bit fixed-base table (about 12 MiB of
	// normalized curve points).
	ProfileCompact CommitterProfile = "compact"
	// ProfileFast retains the original Verkle-optimized table (about 334 MiB of
	// normalized curve points).
	ProfileFast CommitterProfile = "fast"
)

// NewScheme creates the original fast IPA commitment scheme. New browser
// callers should select a profile explicitly with NewCommitterScheme.
func NewScheme() (*Scheme, error) {
	return NewCommitterScheme(ProfileFast)
}

// NewVerifierScheme creates an IPA verification scheme without a fixed-base
// commitment table. Its execution methods fail closed if called.
func NewVerifierScheme() (*Scheme, error) {
	return &Scheme{
		ipaConfig:    ipa.NewIPASettingsForVerifier(),
		verifierOnly: true,
	}, nil
}

// NewCommitterScheme creates an IPA scheme using one explicit MSM profile.
func NewCommitterScheme(profile CommitterProfile) (*Scheme, error) {
	var upstreamProfile ipa.MSMProfile
	switch profile {
	case ProfileDirect:
		upstreamProfile = ipa.MSMProfileDirect
	case ProfileCompact:
		upstreamProfile = ipa.MSMProfileCompact
	case ProfileFast:
		upstreamProfile = ipa.MSMProfileFast
	default:
		return nil, fmt.Errorf("unsupported IPA committer profile %q", profile)
	}

	ipaConfig, err := ipa.NewIPASettingsWithProfile(upstreamProfile)
	if err != nil {
		return nil, fmt.Errorf("failed to create IPA %s settings: %w", profile, err)
	}

	return &Scheme{
		ipaConfig: ipaConfig,
		profile:   profile,
	}, nil
}

// CommitterProfile reports the selected execution profile. The second return
// value is false for a verification-only scheme.
func (s *Scheme) CommitterProfile() (CommitterProfile, bool) {
	if s == nil || s.verifierOnly {
		return "", false
	}
	return s.profile, true
}

// ParameterSHA256 fingerprints the domain-separated compressed SRS followed
// by Q. It is suitable for release provenance and is independent of the
// committer performance profile.
func ParameterSHA256() string {
	config := ipa.NewIPASettingsForVerifier()
	digest := sha256.New()
	_, _ = digest.Write([]byte(ParameterSetID))
	_, _ = digest.Write([]byte{0})
	for i := range config.SRS {
		point := config.SRS[i].Bytes()
		_, _ = digest.Write(point[:])
	}
	q := config.Q.Bytes()
	_, _ = digest.Write(q[:])
	return hex.EncodeToString(digest.Sum(nil))
}

// MaxValues returns the maximum number of authenticated slots.
func (s *Scheme) MaxValues() int {
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
	value, proof, err := s.proveValuesIndex(comm, values, index)
	return comm, value, proof, err
}

// ProveAtRoot opens values against a caller-supplied root without recomputing
// the IPA commitment. The generated proof is verified before it is returned so
// inconsistent client materialization fails closed.
func (s *Scheme) ProveAtRoot(root cid.Cid, values []commitment.Cell, index uint64) (commitment.Cell, []byte, error) {
	if err := s.requireCommitter(); err != nil {
		return nil, nil, err
	}
	if _, err := maltcid.ExtractCommitment(root); err != nil {
		return nil, nil, fmt.Errorf("invalid proof root: %w", err)
	}
	if maltcid.BackendKindOf(root) != maltcid.BackendKindIPA {
		return nil, nil, fmt.Errorf("proof root does not use the IPA backend")
	}
	if len(values) > MaxValues {
		return nil, nil, fmt.Errorf("too many values: %d > %d", len(values), MaxValues)
	}
	if index >= uint64(len(values)) {
		return nil, nil, fmt.Errorf("index %d out of range", index)
	}
	value, proof, err := s.proveValuesIndex(root, values, index)
	if err != nil {
		return nil, nil, err
	}
	ok, err := s.VerifyIndex(root, index, value, append([]byte(nil), proof...))
	if err != nil {
		return nil, nil, fmt.Errorf("verify root-bound IPA proof: %w", err)
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
// whose Open method reuses that commitment in the IPA transcript.
func (s *Scheme) PrepareOpening(values []commitment.Cell) (commitment.IndexOpening, error) {
	if err := s.requireCommitter(); err != nil {
		return nil, err
	}
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
	return o.scheme.proveValuesIndex(o.root, o.values, index)
}

// BatchProve proves multiple stable indices with one batch proof payload.
func (s *Scheme) BatchProve(values []commitment.Cell, indices []uint64) (cid.Cid, []commitment.Cell, []byte, error) {
	if err := validateBatchOpening(values, indices); err != nil {
		return cid.Undef, nil, nil, err
	}
	comm, err := s.commitValues(values)
	if err != nil {
		return cid.Undef, nil, nil, err
	}

	commBytes, err := maltcid.ExtractCommitment(comm)
	if err != nil {
		return cid.Undef, nil, nil, fmt.Errorf("failed to extract commitment: %w", err)
	}

	var c banderwagon.Element
	if err := c.SetBytes(commBytes); err != nil {
		return cid.Undef, nil, nil, fmt.Errorf("failed to reconstruct commitment: %w", err)
	}

	vector := valuesToVector(values)
	commitments := make([]banderwagon.Element, len(indices))
	cs := make([]*banderwagon.Element, len(indices))
	fs := make([][]fr.Element, len(indices))
	zs := make([]uint8, len(indices))
	proved := make([]commitment.Cell, len(indices))
	for i, index := range indices {
		commitments[i] = c
		cs[i] = &commitments[i]
		fs[i] = vector
		zs[i] = uint8(index)
		proved[i] = commitment.NewCell(values[int(index)])
	}

	transcript := common.NewTranscript(batchTranscriptLabel)
	proof, err := multiproof.CreateMultiProof(transcript, s.ipaConfig, cs, fs, zs)
	if err != nil {
		return cid.Undef, nil, nil, fmt.Errorf("failed to create IPA batch proof: %w", err)
	}

	proofBytes, err := serializeMultiProof(proof)
	if err != nil {
		return cid.Undef, nil, nil, fmt.Errorf("failed to serialize IPA batch proof: %w", err)
	}
	return comm, proved, proofBytes, nil
}

// BatchProveAtRoot opens values against a caller-supplied root without
// recomputing the IPA commitment.
func (s *Scheme) BatchProveAtRoot(root cid.Cid, values []commitment.Cell, indices []uint64) ([]commitment.Cell, []byte, error) {
	if err := s.requireCommitter(); err != nil {
		return nil, nil, err
	}
	if _, err := maltcid.ExtractCommitment(root); err != nil {
		return nil, nil, fmt.Errorf("invalid proof root: %w", err)
	}
	if maltcid.BackendKindOf(root) != maltcid.BackendKindIPA {
		return nil, nil, fmt.Errorf("proof root does not use the IPA backend")
	}
	if err := validateBatchOpening(values, indices); err != nil {
		return nil, nil, err
	}

	commBytes, err := maltcid.ExtractCommitment(root)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract commitment: %w", err)
	}
	var c banderwagon.Element
	if err := c.SetBytes(commBytes); err != nil {
		return nil, nil, fmt.Errorf("failed to reconstruct commitment: %w", err)
	}

	vector := valuesToVector(values)
	commitments := make([]banderwagon.Element, len(indices))
	cs := make([]*banderwagon.Element, len(indices))
	fs := make([][]fr.Element, len(indices))
	zs := make([]uint8, len(indices))
	proved := make([]commitment.Cell, len(indices))
	for i, index := range indices {
		commitments[i] = c
		cs[i] = &commitments[i]
		fs[i] = vector
		zs[i] = uint8(index)
		proved[i] = commitment.NewCell(values[int(index)])
	}

	transcript := common.NewTranscript(batchTranscriptLabel)
	batchProof, err := multiproof.CreateMultiProof(transcript, s.ipaConfig, cs, fs, zs)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create IPA batch proof: %w", err)
	}
	proof, err := serializeMultiProof(batchProof)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to serialize IPA batch proof: %w", err)
	}
	ok, err := s.BatchVerify(root, indices, proved, append([]byte(nil), proof...))
	if err != nil {
		return nil, nil, fmt.Errorf("verify root-bound IPA batch proof: %w", err)
	}
	if !ok {
		return nil, nil, commitment.ErrInvalidCommitment
	}
	return proved, proof, nil
}

func (s *Scheme) proveValuesIndex(comm cid.Cid, values []commitment.Cell, index uint64) (commitment.Cell, []byte, error) {
	vector := valuesToVector(values)
	commBytes, err := maltcid.ExtractCommitment(comm)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract commitment: %w", err)
	}

	transcript := common.NewTranscript(singleTranscriptLabel)

	var c banderwagon.Element
	if err := c.SetBytes(commBytes); err != nil {
		return nil, nil, fmt.Errorf("failed to reconstruct commitment: %w", err)
	}

	var evalPoint fr.Element
	evalPoint.SetUint64(index)

	proof, err := ipa.CreateIPAProof(transcript, s.ipaConfig, c, vector, evalPoint)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create IPA proof: %w", err)
	}

	proofBytes, err := s.serializeProof(&proof, int(index))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to serialize proof: %w", err)
	}

	valueIndex := int(index)
	if valueIndex < 0 || valueIndex >= len(values) {
		return nil, nil, fmt.Errorf("index %d out of range", index)
	}
	return commitment.NewCell(values[valueIndex]), proofBytes, nil
}

// VerifyIndex verifies a proof for a stable index without requiring cache state.
func (s *Scheme) VerifyIndex(comm cid.Cid, index uint64, value commitment.Cell, proof []byte) (bool, error) {
	if index >= MaxValues {
		return false, fmt.Errorf("index %d exceeds max %d", index, MaxValues-1)
	}
	commBytes, err := maltcid.ExtractCommitment(comm)
	if err != nil {
		return false, fmt.Errorf("failed to extract commitment: %w", err)
	}

	ipaProof, evalPoint, err := s.deserializeProof(proof)
	if err != nil {
		return false, fmt.Errorf("failed to deserialize proof: %w", err)
	}
	if evalPoint != index {
		return false, nil
	}

	transcript := common.NewTranscript(singleTranscriptLabel)

	var c banderwagon.Element
	if err := c.SetBytes(commBytes); err != nil {
		return false, fmt.Errorf("failed to reconstruct commitment: %w", err)
	}

	var evalPointFr fr.Element
	evalPointFr.SetUint64(index)

	output := cellToFieldElement(value)
	ok, err := ipa.CheckIPAProof(transcript, s.ipaConfig, c, *ipaProof, evalPointFr, output)
	if err != nil {
		return false, fmt.Errorf("failed to check IPA proof: %w", err)
	}
	return ok, nil
}

// BatchVerify verifies a batch proof for an ordered index list.
func (s *Scheme) BatchVerify(comm cid.Cid, indices []uint64, values []commitment.Cell, proof []byte) (bool, error) {
	if err := validateBatchVerification(indices, values); err != nil {
		return false, err
	}

	commBytes, err := maltcid.ExtractCommitment(comm)
	if err != nil {
		return false, fmt.Errorf("failed to extract commitment: %w", err)
	}

	var c banderwagon.Element
	if err := c.SetBytes(commBytes); err != nil {
		return false, fmt.Errorf("failed to reconstruct commitment: %w", err)
	}

	mp, err := deserializeMultiProof(proof)
	if err != nil {
		return false, fmt.Errorf("failed to deserialize IPA batch proof: %w", err)
	}

	commitments := make([]banderwagon.Element, len(indices))
	cs := make([]*banderwagon.Element, len(indices))
	outputs := make([]fr.Element, len(indices))
	ys := make([]*fr.Element, len(indices))
	zs := make([]uint8, len(indices))
	for i, index := range indices {
		commitments[i] = c
		cs[i] = &commitments[i]
		outputs[i] = cellToFieldElement(values[i])
		ys[i] = &outputs[i]
		zs[i] = uint8(index)
	}

	transcript := common.NewTranscript(batchTranscriptLabel)
	ok, err := multiproof.CheckMultiProof(transcript, s.ipaConfig, mp, cs, ys, zs)
	if err != nil {
		return false, fmt.Errorf("failed to check IPA batch proof: %w", err)
	}
	return ok, nil
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
func (s *Scheme) VerifyProof(comm cid.Cid, value commitment.Cell, proof []byte) (bool, error) {
	commBytes, err := maltcid.ExtractCommitment(comm)
	if err != nil {
		return false, fmt.Errorf("failed to extract commitment: %w", err)
	}

	ipaProof, index, err := s.deserializeProof(proof)
	if err != nil {
		return false, fmt.Errorf("failed to deserialize proof: %w", err)
	}
	if index >= MaxValues {
		return false, fmt.Errorf("proof index %d exceeds max %d", index, MaxValues-1)
	}

	transcript := common.NewTranscript(singleTranscriptLabel)

	var c banderwagon.Element
	if err := c.SetBytes(commBytes); err != nil {
		return false, fmt.Errorf("failed to reconstruct commitment: %w", err)
	}

	var evalPointFr fr.Element
	evalPointFr.SetUint64(index)

	output := cellToFieldElement(value)
	ok, err := ipa.CheckIPAProof(transcript, s.ipaConfig, c, *ipaProof, evalPointFr, output)
	if err != nil {
		return false, fmt.Errorf("failed to check IPA proof: %w", err)
	}
	return ok, nil
}

// Replace performs an index-stable replacement.
func (s *Scheme) Replace(values []commitment.Cell, index uint64, oldValue, newValue commitment.Cell) (cid.Cid, error) {
	if err := s.requireCommitter(); err != nil {
		return cid.Undef, err
	}
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

// serializeProof serializes an IPA proof with index information.
func (s *Scheme) serializeProof(proof *ipa.IPAProof, index int) ([]byte, error) {
	if len(proof.L) != proofRounds || len(proof.R) != proofRounds {
		return nil, fmt.Errorf("IPA proof has %d L and %d R rounds, want %d each", len(proof.L), len(proof.R), proofRounds)
	}
	numRounds := proofRounds

	result := make([]byte, ProofSize)
	binary.BigEndian.PutUint32(result[0:4], uint32(numRounds))

	offset := 4
	for _, p := range proof.L {
		pb := p.Bytes()
		copy(result[offset:offset+32], pb[:])
		offset += 32
	}
	for _, p := range proof.R {
		pb := p.Bytes()
		copy(result[offset:offset+32], pb[:])
		offset += 32
	}
	as := proof.A_scalar.BytesLE()
	copy(result[offset:offset+32], as[:])
	offset += 32

	binary.BigEndian.PutUint32(result[offset:offset+4], uint32(index))

	return result, nil
}

// deserializeProof deserializes an IPA proof and returns the proof and index.
func (s *Scheme) deserializeProof(data []byte) (*ipa.IPAProof, uint64, error) {
	if len(data) != ProofSize {
		return nil, 0, fmt.Errorf("proof data has wrong size: expected %d, got %d", ProofSize, len(data))
	}

	rawRounds := binary.BigEndian.Uint32(data[0:4])
	if rawRounds != uint32(proofRounds) {
		return nil, 0, fmt.Errorf("proof has %d rounds, want %d", rawRounds, proofRounds)
	}
	numRounds := proofRounds

	proof := &ipa.IPAProof{
		L: make([]banderwagon.Element, numRounds),
		R: make([]banderwagon.Element, numRounds),
	}

	offset := 4
	for i := 0; i < numRounds; i++ {
		if err := proof.L[i].SetBytes(data[offset : offset+32]); err != nil {
			return nil, 0, fmt.Errorf("failed to parse L[%d]: %w", i, err)
		}
		offset += 32
	}
	for i := 0; i < numRounds; i++ {
		if err := proof.R[i].SetBytes(data[offset : offset+32]); err != nil {
			return nil, 0, fmt.Errorf("failed to parse R[%d]: %w", i, err)
		}
		offset += 32
	}

	proof.A_scalar.SetBytesLE(data[offset : offset+32])
	offset += 32

	index := uint64(binary.BigEndian.Uint32(data[offset : offset+4]))

	return proof, index, nil
}

func serializeMultiProof(proof *multiproof.MultiProof) ([]byte, error) {
	var buf bytes.Buffer
	if err := proof.Write(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func deserializeMultiProof(data []byte) (*multiproof.MultiProof, error) {
	var proof multiproof.MultiProof
	if err := proof.Read(bytes.NewReader(data)); err != nil {
		return nil, err
	}
	return &proof, nil
}

func cellToFieldElement(cell commitment.Cell) fr.Element {
	var result fr.Element
	h := sha256.Sum256(cell)
	result.SetBytes(h[:])
	return result
}

func (s *Scheme) commitValues(values []commitment.Cell) (cid.Cid, error) {
	if err := s.requireCommitter(); err != nil {
		return cid.Undef, err
	}
	if len(values) > MaxValues {
		return cid.Cid{}, fmt.Errorf("too many values: %d > %d", len(values), MaxValues)
	}

	vector := valuesToVector(values)

	comm, err := s.ipaConfig.CommitWithError(vector)
	if err != nil {
		return cid.Undef, fmt.Errorf("commit IPA vector: %w", err)
	}
	commBytes := comm.Bytes()
	return maltcid.NewIPACid(commBytes[:])
}

func (s *Scheme) requireCommitter() error {
	if s == nil || s.ipaConfig == nil {
		return fmt.Errorf("IPA scheme is nil")
	}
	if s.verifierOnly {
		return fmt.Errorf("IPA scheme is verification-only")
	}
	return nil
}

func valuesToVector(values []commitment.Cell) []fr.Element {
	vector := make([]fr.Element, MaxValues)
	zero := fr.Element{}
	zero.SetZero()
	for i := range vector {
		vector[i] = zero
	}
	for i, value := range values {
		vector[i] = cellToFieldElement(value)
	}
	return vector
}

// Ensure Scheme implements commitment.IndexCommitment.
var _ commitment.IndexCommitment = (*Scheme)(nil)
var _ commitment.IndexVerifier = (*Scheme)(nil)
var _ commitment.IndexProver = (*Scheme)(nil)
var _ commitment.IndexRootProver = (*Scheme)(nil)

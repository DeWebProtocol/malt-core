package kzg

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"

	blsfr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	gokzg4844 "github.com/crate-crypto/go-kzg-4844"
)

// OpeningComputer computes the G1 quotient commitment for KZG4096. Evaluations
// contain exactly MaxValues canonical big-endian BLS12-381 scalars in the
// profile's bit-reversed evaluation-domain order. The result is a canonical
// compressed G1 point. It must permit concurrent calls and must not retain or
// modify the supplied evaluations. Device lifetime and scheduling belong to
// the host; this interface has no storage, service or CUDA dependency.
type OpeningComputer interface {
	Open(evaluations [][32]byte, index uint64) ([48]byte, error)
}

// NewSchemeWithOpeningComputer accelerates only proof computation. Commitment
// construction and verification retain the built-in CPU implementation. Prove
// verifies the result against the selected root; callers of prepared Open must
// verify it as required by commitment.Opening's contract.
func NewSchemeWithOpeningComputer(computer OpeningComputer) (*Scheme, error) {
	if isNilComputer(computer) {
		return nil, errors.New("KZG opening computer is required")
	}
	s, err := NewScheme()
	if err != nil {
		return nil, err
	}
	s.computer = computer
	return s, nil
}

func isNilComputer(computer OpeningComputer) bool {
	if computer == nil {
		return true
	}
	v := reflect.ValueOf(computer)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return v.IsNil()
	}
	return false
}

// OpeningParameters returns detached canonical uncompressed G1 coordinates for
// the exact KZG4096 writer setup (MaxValues pairs of 48-byte big-endian X/Y).
// These are public parameters, not a secret key. No device package is linked.
func OpeningParameters() ([]byte, error) {
	if _, err := loadKZGWriterKey(); err != nil {
		return nil, err
	}
	return bytes.Clone(trustedSetupWriterBytes), nil
}

func (s *Scheme) openPolynomial(polynomial []blsfr.Element, index uint64) (gokzg4844.KZGProof, gokzg4844.Scalar, error) {
	if s.computer == nil {
		return provePolynomialAtIndex(s.writerKey, s.domain, polynomial, index)
	}
	if len(polynomial) != MaxValues || index >= MaxValues {
		return gokzg4844.KZGProof{}, gokzg4844.Scalar{}, errors.New("invalid accelerated KZG opening")
	}
	evaluations := make([][32]byte, MaxValues)
	for i := range polynomial {
		evaluations[i] = polynomial[i].Bytes()
	}
	point, err := s.computer.Open(evaluations, index)
	if err != nil {
		return gokzg4844.KZGProof{}, gokzg4844.Scalar{}, fmt.Errorf("KZG opening computer: %w", err)
	}
	proof := gokzg4844.KZGProof(point)
	if _, err := gokzg4844.DeserializeKZGProof(proof); err != nil {
		return gokzg4844.KZGProof{}, gokzg4844.Scalar{}, fmt.Errorf("invalid accelerated KZG point: %w", err)
	}
	return proof, gokzg4844.SerializeScalar(polynomial[index]), nil
}

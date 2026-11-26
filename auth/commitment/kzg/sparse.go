package kzg

import (
	"fmt"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	blsfr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	gokzg4844 "github.com/crate-crypto/go-kzg-4844"
)

func provePolynomialAtIndex(key *kzgWriterKey, domain *kzgDomain, polynomial []blsfr.Element, index uint64) (gokzg4844.KZGProof, gokzg4844.Scalar, error) {
	if key == nil || len(key.lagrangeG1) != MaxValues || len(key.unitProofs) != MaxValues {
		return gokzg4844.KZGProof{}, gokzg4844.Scalar{}, fmt.Errorf("KZG writer parameters are incomplete")
	}
	if domain == nil || len(domain.roots) != MaxValues {
		return gokzg4844.KZGProof{}, gokzg4844.Scalar{}, fmt.Errorf("KZG domain is incomplete")
	}
	if len(polynomial) != MaxValues || index >= MaxValues {
		return gokzg4844.KZGProof{}, gokzg4844.Scalar{}, fmt.Errorf("invalid KZG opening index %d", index)
	}
	indices := make([]int, 0, 128)
	for i := range polynomial {
		if !polynomial[i].IsZero() {
			indices = append(indices, i)
		}
	}
	return proveSparsePolynomial(key, domain, polynomial, index, indices)
}

// At z=omega_i, write p=p_i*L_i+sum(j!=i) p_j*L_j. The unit proof U_i
// commits to (L_i(X)-1)/(X-omega_i). Each other term has evaluations
// p_j/(omega_j-omega_i) at j, -p_j*omega_j/(omega_i*(omega_j-omega_i))
// at i, and zero elsewhere. Linearity therefore gives exactly the same
// quotient commitment as the dense algorithm, including when p_i is zero.
func proveSparsePolynomial(key *kzgWriterKey, domain *kzgDomain, polynomial []blsfr.Element, index uint64, indices []int) (gokzg4844.KZGProof, gokzg4844.Scalar, error) {
	denominators := make([]blsfr.Element, len(indices))
	for k, j := range indices {
		denominators[k].Sub(&domain.roots[j], &domain.roots[index])
	}
	// BatchInvert leaves a zero denominator at j=i as zero. That term is
	// handled separately using U_i, never by division at the opening point.
	inverses := blsfr.BatchInvert(denominators)
	points := make([]bls12381.G1Affine, 0, len(indices)+2)
	scalars := make([]blsfr.Element, 0, len(indices)+2)
	var invZ, diagonal blsfr.Element
	invZ.Inverse(&domain.roots[index])
	for k, j := range indices {
		if uint64(j) == index {
			continue
		}
		var scalar, correction blsfr.Element
		scalar.Mul(&polynomial[j], &inverses[k])
		points = append(points, key.lagrangeG1[j])
		scalars = append(scalars, scalar)
		correction.Mul(&scalar, &domain.roots[j])
		correction.Mul(&correction, &invZ)
		diagonal.Sub(&diagonal, &correction)
	}
	points = append(points, key.lagrangeG1[index], key.unitProofs[index])
	scalars = append(scalars, diagonal, polynomial[index])
	var proof bls12381.G1Affine
	if _, err := proof.MultiExp(points, scalars, msmConfig()); err != nil {
		return gokzg4844.KZGProof{}, gokzg4844.Scalar{}, err
	}
	return gokzg4844.KZGProof(proof.Bytes()), gokzg4844.SerializeScalar(polynomial[index]), nil
}

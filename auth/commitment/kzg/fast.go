package kzg

import (
	"fmt"
	"math/big"
	"math/bits"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	blsfr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	gokzg4844 "github.com/crate-crypto/go-kzg-4844"
	"github.com/dewebprotocol/malt/auth/commitment"
)

type kzgDomain struct {
	roots []blsfr.Element
}

var (
	domainOnce sync.Once
	domain4096 *kzgDomain
	domainErr  error
)

func loadKZGDomain() (*kzgDomain, error) {
	domainOnce.Do(func() {
		domain4096, domainErr = buildKZGDomain(MaxValues)
	})
	return domain4096, domainErr
}

func buildKZGDomain(size int) (*kzgDomain, error) {
	if bits.OnesCount(uint(size)) != 1 {
		return nil, fmt.Errorf("domain size %d is not a power of two", size)
	}

	var rootOfUnity blsfr.Element
	if _, err := rootOfUnity.SetString("10238227357739495823651030575849232062558860180284477541189508159991286009131"); err != nil {
		return nil, err
	}
	const maxOrderRoot = 32
	logx := bits.TrailingZeros(uint(size))
	if logx > maxOrderRoot {
		return nil, fmt.Errorf("domain size %d exceeds supported root order", size)
	}

	var generator blsfr.Element
	exponent := uint64(1 << (maxOrderRoot - logx))
	generator.Exp(rootOfUnity, new(big.Int).SetUint64(exponent))
	roots := make([]blsfr.Element, size)
	current := blsfr.One()
	for i := range roots {
		roots[i] = current
		current.Mul(&current, &generator)
	}
	bitReverseFieldElements(roots)

	return &kzgDomain{roots: roots}, nil
}

func bitReverseFieldElements(values []blsfr.Element) {
	bitLen := bits.Len(uint(len(values))) - 1
	for i := range values {
		j := int(bits.Reverse(uint(i)) >> (bits.UintSize - bitLen))
		if j > i {
			values[i], values[j] = values[j], values[i]
		}
	}
}

func polynomialFromValues(values []commitment.Cell) ([]blsfr.Element, error) {
	polynomial := make([]blsfr.Element, MaxValues)
	for i, value := range values {
		scalar, err := gokzg4844.DeserializeScalar(cellToKZGScalar(value))
		if err != nil {
			return nil, fmt.Errorf("decode KZG cell %d: %w", i, err)
		}
		polynomial[i] = scalar
	}
	return polynomial, nil
}

func commitPolynomial(key *kzgWriterKey, polynomial []blsfr.Element) (gokzg4844.KZGCommitment, error) {
	if key == nil || len(key.lagrangeG1) != MaxValues || len(polynomial) != MaxValues {
		return gokzg4844.KZGCommitment{}, fmt.Errorf("KZG writer parameters are incomplete")
	}
	var result bls12381.G1Affine
	if _, err := result.MultiExp(
		key.lagrangeG1,
		polynomial,
		ecc.MultiExpConfig{NbTasks: 1},
	); err != nil {
		return gokzg4844.KZGCommitment{}, err
	}
	serialized := result.Bytes()
	return gokzg4844.KZGCommitment(serialized), nil
}

func provePolynomialAtIndex(
	key *kzgWriterKey,
	domain *kzgDomain,
	polynomial []blsfr.Element,
	index uint64,
) (gokzg4844.KZGProof, gokzg4844.Scalar, error) {
	if domain == nil || len(domain.roots) != MaxValues {
		return gokzg4844.KZGProof{}, gokzg4844.Scalar{}, fmt.Errorf("KZG domain is incomplete")
	}
	if len(polynomial) != MaxValues || index >= MaxValues {
		return gokzg4844.KZGProof{}, gokzg4844.Scalar{}, fmt.Errorf("invalid KZG opening index %d", index)
	}

	claimed := polynomial[index]
	z := domain.roots[index]
	var invZ blsfr.Element
	invZ.Inverse(&z)
	rootsMinusZ := make([]blsfr.Element, MaxValues)
	for i := range rootsMinusZ {
		rootsMinusZ[i].Sub(&domain.roots[i], &z)
	}
	rootsMinusZ[index].SetOne()
	inverseRootsMinusZ := blsfr.BatchInvert(rootsMinusZ)
	quotient := rootsMinusZ
	quotient[index].SetZero()
	for j := range quotient {
		if uint64(j) == index {
			continue
		}
		var qj blsfr.Element
		qj.Sub(&polynomial[j], &claimed)
		qj.Mul(&qj, &inverseRootsMinusZ[j])
		quotient[j] = qj

		var contribution blsfr.Element
		contribution.Neg(&qj)
		contribution.Mul(&contribution, &domain.roots[j])
		contribution.Mul(&contribution, &invZ)
		quotient[index].Add(&quotient[index], &contribution)
	}

	commitment, err := commitPolynomial(key, quotient)
	if err != nil {
		return gokzg4844.KZGProof{}, gokzg4844.Scalar{}, err
	}
	return gokzg4844.KZGProof(commitment), gokzg4844.SerializeScalar(claimed), nil
}

func verifyKZGOpening(
	key *kzgOpeningKey,
	commitmentBytes gokzg4844.KZGCommitment,
	inputPoint blsfr.Element,
	claimedValueBytes gokzg4844.Scalar,
	proofBytes gokzg4844.KZGProof,
) error {
	if key == nil {
		return fmt.Errorf("KZG verifier parameters are incomplete")
	}
	claimedValue, err := gokzg4844.DeserializeScalar(claimedValueBytes)
	if err != nil {
		return err
	}
	polynomialCommitment, err := gokzg4844.DeserializeKZGCommitment(commitmentBytes)
	if err != nil {
		return err
	}
	quotientCommitment, err := gokzg4844.DeserializeKZGProof(proofBytes)
	if err != nil {
		return err
	}

	var genG2Jac bls12381.G2Jac
	genG2Jac.FromAffine(&key.genG2)
	var inputPointBig big.Int
	inputPoint.BigInt(&inputPointBig)
	var inputPointG2Jac bls12381.G2Jac
	inputPointG2Jac.ScalarMultiplication(&genG2Jac, &inputPointBig)
	var alphaMinusPoint bls12381.G2Jac
	alphaMinusPoint.FromAffine(&key.alphaG2)
	alphaMinusPoint.SubAssign(&inputPointG2Jac)
	var alphaMinusPointAffine bls12381.G2Affine
	alphaMinusPointAffine.FromJacobian(&alphaMinusPoint)

	var genG1Jac bls12381.G1Jac
	genG1Jac.FromAffine(&key.genG1)
	var claimedValueBig big.Int
	claimedValue.BigInt(&claimedValueBig)
	var claimedValueG1 bls12381.G1Jac
	claimedValueG1.ScalarMultiplication(&genG1Jac, &claimedValueBig)
	var commitmentMinusValue bls12381.G1Jac
	commitmentMinusValue.FromAffine(&polynomialCommitment)
	commitmentMinusValue.SubAssign(&claimedValueG1)
	var commitmentMinusValueAffine bls12381.G1Affine
	commitmentMinusValueAffine.FromJacobian(&commitmentMinusValue)

	var negativeG2 bls12381.G2Affine
	negativeG2.Neg(&key.genG2)
	valid, err := bls12381.PairingCheck(
		[]bls12381.G1Affine{commitmentMinusValueAffine, quotientCommitment},
		[]bls12381.G2Affine{negativeG2, alphaMinusPointAffine},
	)
	if err != nil {
		return err
	}
	if !valid {
		return fmt.Errorf("KZG opening proof is invalid")
	}
	return nil
}

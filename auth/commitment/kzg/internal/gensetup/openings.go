package main

import (
	"fmt"
	"math/big"
	"math/bits"
	"runtime"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	blsfr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	gokzg4844 "github.com/crate-crypto/go-kzg-4844"
	"golang.org/x/sync/errgroup"
)

// Derive one public opening U_i of L_i at omega_i for each profile slot.
// Use the independent pinned upstream implementation, and verify every result
// against the source Lagrange commitment before emitting runtime coordinates.
// No application vector, query or secret setup value is involved.
func deriveUnitOpenings(setup trustedSetup) ([]byte, error) {
	parameters := gokzg4844.JSONTrustedSetup{SetupG2: setup.G2Monomial[:2]}
	copy(parameters.SetupG1Lagrange[:], setup.G1Lagrange)
	context, err := gokzg4844.NewContext4096(&parameters)
	if err != nil {
		return nil, fmt.Errorf("initialize unit-opening generator: %w", err)
	}
	var root blsfr.Element
	if _, err := root.SetString("10238227357739495823651030575849232062558860180284477541189508159991286009131"); err != nil {
		return nil, err
	}
	var generator blsfr.Element
	generator.Exp(root, new(big.Int).SetUint64(1<<(32-12)))
	roots := make([]blsfr.Element, setupWidth)
	current := blsfr.One()
	for i := range roots {
		roots[i] = current
		current.Mul(&current, &generator)
	}
	bitReverse(roots)
	const pointSize = bls12381.SizeOfG1AffineUncompressed
	result := make([]byte, setupWidth*pointSize)
	workers := min(runtime.GOMAXPROCS(0), setupWidth)
	var group errgroup.Group
	for worker := range workers {
		group.Go(func() error {
			blob := new(gokzg4844.Blob)
			one := gokzg4844.SerializeScalar(blsfr.One())
			for i := worker; i < setupWidth; i += workers {
				if i >= workers {
					clear(blob[(i-workers)*32 : (i-workers+1)*32])
				}
				copy(blob[i*32:(i+1)*32], one[:])
				point := gokzg4844.SerializeScalar(roots[i])
				proof, claimed, err := context.ComputeKZGProof(blob, point, 1)
				if err != nil {
					return fmt.Errorf("derive unit opening %d: %w", i, err)
				}
				if claimed != one {
					return fmt.Errorf("derive unit opening %d: unexpected claimed value", i)
				}
				sourceIndex := int(bits.Reverse(uint(i)) >> (bits.UintSize - 12))
				encoded, err := decodeHex(setup.G1Lagrange[sourceIndex])
				if err != nil {
					return err
				}
				var commitment gokzg4844.KZGCommitment
				copy(commitment[:], encoded)
				if err := context.VerifyKZGProof(commitment, point, claimed, proof); err != nil {
					return fmt.Errorf("verify unit opening %d: %w", i, err)
				}
				var affine bls12381.G1Affine
				if _, err := affine.SetBytes(proof[:]); err != nil {
					return fmt.Errorf("validate unit opening %d: %w", i, err)
				}
				raw := affine.RawBytes()
				copy(result[i*pointSize:(i+1)*pointSize], raw[:])
			}
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return nil, err
	}
	return result, nil
}

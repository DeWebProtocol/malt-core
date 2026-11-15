package kzg

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"sync"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// Regenerate only from the exact go-kzg version and setup digest enforced by
// internal/gensetup. The generated assets are checked into the repository so
// ordinary builds do not depend on a module cache or network access.
//go:generate go run ./internal/gensetup

//go:embed trusted_setup_verifier.bin
var trustedSetupVerifierBytes []byte

//go:embed trusted_setup_writer.bin
var trustedSetupWriterBytes []byte

// These unit-polynomial openings are derived from the same public setup, not
// additional ceremony material. Only writers load or link this fixed table.
//
//go:embed trusted_setup_openings.bin
var trustedSetupOpeningBytes []byte

type kzgOpeningKey struct {
	genG1   bls12381.G1Affine
	genG2   bls12381.G2Affine
	alphaG2 bls12381.G2Affine
}

type kzgWriterKey struct {
	lagrangeG1 []bls12381.G1Affine
	unitProofs []bls12381.G1Affine
}

var (
	openingKeyOnce sync.Once
	openingKey     *kzgOpeningKey
	openingKeyErr  error
	writerKeyOnce  sync.Once
	writerKey      *kzgWriterKey
	writerKeyErr   error
)

func loadKZGOpeningKey() (*kzgOpeningKey, error) {
	openingKeyOnce.Do(func() {
		if err := verifySetupAsset("verifier", trustedSetupVerifierBytes, trustedSetupVerifierSHA256); err != nil {
			openingKeyErr = err
			return
		}
		const pointSize = bls12381.SizeOfG2AffineCompressed
		if len(trustedSetupVerifierBytes) != 2*pointSize {
			openingKeyErr = fmt.Errorf("KZG verifier setup has %d bytes, want %d", len(trustedSetupVerifierBytes), 2*pointSize)
			return
		}
		key := new(kzgOpeningKey)
		_, _, key.genG1, _ = bls12381.Generators()
		if _, err := key.genG2.SetBytes(trustedSetupVerifierBytes[:pointSize]); err != nil {
			openingKeyErr = fmt.Errorf("decode KZG G2 generator: %w", err)
			return
		}
		if _, err := key.alphaG2.SetBytes(trustedSetupVerifierBytes[pointSize:]); err != nil {
			openingKeyErr = fmt.Errorf("decode KZG alpha G2: %w", err)
			return
		}
		openingKey = key
	})
	if openingKeyErr != nil {
		return nil, openingKeyErr
	}
	return openingKey, nil
}

func loadKZGWriterKey() (*kzgWriterKey, error) {
	writerKeyOnce.Do(func() {
		points, err := decodeG1Asset("writer", trustedSetupWriterBytes, trustedSetupWriterSHA256)
		if err != nil {
			writerKeyErr = err
			return
		}
		unitProofs, err := decodeG1Asset("unit openings", trustedSetupOpeningBytes, trustedSetupOpeningsSHA256)
		if err != nil {
			writerKeyErr = err
			return
		}
		writerKey = &kzgWriterKey{lagrangeG1: points, unitProofs: unitProofs}
	})
	if writerKeyErr != nil {
		return nil, writerKeyErr
	}
	return writerKey, nil
}

func decodeG1Asset(name string, data []byte, expected string) ([]bls12381.G1Affine, error) {
	if err := verifySetupAsset(name, data, expected); err != nil {
		return nil, err
	}
	const pointSize = bls12381.SizeOfG1AffineUncompressed
	if len(data) != MaxValues*pointSize {
		return nil, fmt.Errorf("KZG %s setup has %d bytes, want %d", name, len(data), MaxValues*pointSize)
	}
	points := make([]bls12381.G1Affine, MaxValues)
	for i := range points {
		raw := data[i*pointSize : (i+1)*pointSize]
		// gensetup validates the curve/subgroup and each derived opening.
		// The fingerprint binds these canonical coordinates, so runtime
		// initialization only decodes the two field elements.
		if err := points[i].X.SetBytesCanonical(raw[:48]); err != nil {
			return nil, fmt.Errorf("decode KZG %s point %d X: %w", name, i, err)
		}
		if err := points[i].Y.SetBytesCanonical(raw[48:]); err != nil {
			return nil, fmt.Errorf("decode KZG %s point %d Y: %w", name, i, err)
		}
	}
	return points, nil
}

func verifySetupAsset(name string, data []byte, expected string) error {
	digest := sha256.Sum256(data)
	if got := hex.EncodeToString(digest[:]); got != expected {
		return fmt.Errorf("KZG %s setup SHA-256 %s, want %s", name, got, expected)
	}
	return nil
}

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

type kzgOpeningKey struct {
	genG1   bls12381.G1Affine
	genG2   bls12381.G2Affine
	alphaG2 bls12381.G2Affine
}

type kzgWriterKey struct {
	lagrangeG1 []bls12381.G1Affine
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
		if err := verifySetupAsset("writer", trustedSetupWriterBytes, trustedSetupWriterSHA256); err != nil {
			writerKeyErr = err
			return
		}
		const pointSize = bls12381.SizeOfG1AffineUncompressed
		if len(trustedSetupWriterBytes) != MaxValues*pointSize {
			writerKeyErr = fmt.Errorf("KZG writer setup has %d bytes, want %d", len(trustedSetupWriterBytes), MaxValues*pointSize)
			return
		}
		points := make([]bls12381.G1Affine, MaxValues)
		for i := range points {
			raw := trustedSetupWriterBytes[i*pointSize : (i+1)*pointSize]
			// gensetup performed the expensive curve and subgroup validation.
			// The embedded asset fingerprint binds these canonical coordinates,
			// so runtime initialization only decodes the two field elements.
			if err := points[i].X.SetBytesCanonical(raw[:48]); err != nil {
				writerKeyErr = fmt.Errorf("decode KZG writer point %d X: %w", i, err)
				return
			}
			if err := points[i].Y.SetBytesCanonical(raw[48:]); err != nil {
				writerKeyErr = fmt.Errorf("decode KZG writer point %d Y: %w", i, err)
				return
			}
		}
		writerKey = &kzgWriterKey{lagrangeG1: points}
	})
	if writerKeyErr != nil {
		return nil, writerKeyErr
	}
	return writerKey, nil
}

func verifySetupAsset(name string, data []byte, expected string) error {
	digest := sha256.Sum256(data)
	if got := hex.EncodeToString(digest[:]); got != expected {
		return fmt.Errorf("KZG %s setup SHA-256 %s, want %s", name, got, expected)
	}
	return nil
}

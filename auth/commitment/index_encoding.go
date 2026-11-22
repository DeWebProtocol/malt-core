package commitment

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/dewebprotocol/malt-core/maltcid"
)

// KZGCellScalar is the canonical big-endian claimed value for a KZG4096 cell.
func KZGCellScalar(cell Cell) (scalar [32]byte) {
	if len(cell) != 0 {
		digest := sha256.Sum256(cell)
		n := new(big.Int).SetBytes(digest[:])
		n.Mod(n, kzgScalarModulus).FillBytes(scalar[:])
	}
	return scalar
}

var kzgScalarModulus, _ = new(big.Int).SetString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)

// WitnessSize gives the primitive bytes independent of the opened cell and slot.
func WitnessSize(profile maltcid.ProfileID) int {
	switch profile {
	case maltcid.KZG4096:
		return 48
	case maltcid.IPA256:
		return 16*32 + 32
	default:
		return 0
	}
}

// ExpandIndexWitness restores the primitive Prove/VerifyIndex encoding.
func ExpandIndexWitness(profile maltcid.ProfileID, slot uint64, cell Cell, witness []byte) ([]byte, error) {
	if len(witness) != WitnessSize(profile) {
		return nil, errors.New("incorrect index witness length")
	}
	var proof []byte
	switch profile {
	case maltcid.KZG4096:
		if slot >= 4096 {
			return nil, errors.New("KZG slot out of range")
		}
		scalar := KZGCellScalar(cell)
		proof = make([]byte, 0, 84)
		proof = append(proof, witness...)
		proof = append(proof, scalar[:]...)
	case maltcid.IPA256:
		if slot >= 256 {
			return nil, errors.New("IPA slot out of range")
		}
		proof = make([]byte, 0, 552)
		proof = binary.BigEndian.AppendUint32(proof, 8)
		proof = append(proof, witness...)
	default:
		return nil, errors.New("unknown index witness profile")
	}
	return binary.BigEndian.AppendUint32(proof, uint32(slot)), nil
}

// IndexWitness checks every omitted field before projecting a primitive proof.
func IndexWitness(profile maltcid.ProfileID, slot uint64, cell Cell, proof []byte) ([]byte, error) {
	start := 0
	if profile == maltcid.IPA256 {
		start = 4
	}
	end := start + WitnessSize(profile)
	if len(proof) < end {
		return nil, errors.New("truncated index proof")
	}
	witness := proof[start:end]
	full, err := ExpandIndexWitness(profile, slot, cell, witness)
	if err != nil || !bytes.Equal(full, proof) {
		return nil, errors.New("index proof does not match opened cell and slot")
	}
	return witness, nil
}

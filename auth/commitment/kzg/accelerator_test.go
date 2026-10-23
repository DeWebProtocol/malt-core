package kzg

import (
	"bytes"
	"errors"
	"testing"

	blsfr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/dewebprotocol/malt-core/auth/commitment"
)

type computerFunc func([][32]byte, uint64) ([48]byte, error)

type pointerComputer struct{}

func (*pointerComputer) Open([][32]byte, uint64) ([48]byte, error) { return [48]byte{}, nil }

func (f computerFunc) Open(p [][32]byte, i uint64) ([48]byte, error) { return f(p, i) }

func TestOpeningComputerPreservesProfileProofsAndRootBinding(t *testing.T) {
	cpu, err := NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	accelerated, err := NewSchemeWithOpeningComputer(computerFunc(func(raw [][32]byte, index uint64) ([48]byte, error) {
		calls++
		if len(raw) != MaxValues {
			t.Fatalf("vector width %d", len(raw))
		}
		p := make([]blsfr.Element, len(raw))
		for i := range p {
			if err := p[i].SetBytesCanonical(raw[i][:]); err != nil {
				t.Fatal(err)
			}
		}
		proof, _, err := provePolynomialAtIndex(cpu.writerKey, cpu.domain, p, index)
		return [48]byte(proof), err
	}))
	if err != nil {
		t.Fatal(err)
	}
	cells := make([]commitment.Cell, MaxValues)
	for i := range cells {
		cells[i] = commitment.NewCell([]byte{byte(i), byte(i >> 8)})
	}
	root, err := cpu.Commit(cells)
	if err != nil {
		t.Fatal(err)
	}
	otherRoot, err := accelerated.Commit(cells)
	if err != nil || !otherRoot.Equals(root) || calls != 0 {
		t.Fatal("commit must remain CPU", err)
	}
	prepared, err := accelerated.PrepareOpening(root, cells)
	if err != nil {
		t.Fatal(err)
	}
	for _, index := range []uint64{0, 1, 127, 4095} {
		value, proof, err := prepared.Open(index)
		if err != nil {
			t.Fatal(err)
		}
		_, expected, err := cpu.Prove(root, cells, index)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(proof, expected) {
			t.Fatalf("proof mismatch at %d", index)
		}
		if ok, err := cpu.VerifyIndex(root, index, value, proof); err != nil || !ok {
			t.Fatal("verification", err)
		}
	}
	wrong := commitment.CloneCells(cells)
	wrong[0] = commitment.NewCell([]byte("wrong"))
	if _, _, err := accelerated.Prove(root, wrong, 0); err == nil {
		t.Fatal("inconsistent root accepted")
	}
	values, proof, err := accelerated.BatchProve(root, cells, []uint64{1, 4095})
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := cpu.BatchVerify(root, []uint64{1, 4095}, values, proof); err != nil || !ok {
		t.Fatal(err)
	}
	parameters, err := OpeningParameters()
	if err != nil {
		t.Fatal(err)
	}
	parameters[0] ^= 1
	second, err := OpeningParameters()
	if err != nil || bytes.Equal(parameters, second) {
		t.Fatal("parameters alias", err)
	}
}

func TestOpeningComputerErrorsNeverFallBackSilently(t *testing.T) {
	sentinel := errors.New("device unavailable")
	s, err := NewSchemeWithOpeningComputer(computerFunc(func([][32]byte, uint64) ([48]byte, error) { return [48]byte{}, sentinel }))
	if err != nil {
		t.Fatal(err)
	}
	cells := []commitment.Cell{commitment.NewCell([]byte("one"))}
	root, err := s.Commit(cells)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Prove(root, cells, 0); !errors.Is(err, sentinel) {
		t.Fatalf("error lost: %v", err)
	}
	if _, err := NewSchemeWithOpeningComputer(nil); err == nil {
		t.Fatal("nil accepted")
	}
	var f computerFunc
	var p *pointerComputer
	for _, c := range []OpeningComputer{f, p} {
		if _, err := NewSchemeWithOpeningComputer(c); err == nil {
			t.Fatal("typed nil accepted")
		}
	}
}

func TestOpeningComputerPreservesEmptyCellEncoding(t *testing.T) {
	cpu, err := NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	accelerated, err := NewSchemeWithOpeningComputer(computerFunc(func(raw [][32]byte, index uint64) ([48]byte, error) {
		p := make([]blsfr.Element, len(raw))
		for i := range p {
			if err := p[i].SetBytesCanonical(raw[i][:]); err != nil {
				return [48]byte{}, err
			}
		}
		proof, _, err := provePolynomialAtIndex(cpu.writerKey, cpu.domain, p, index)
		return [48]byte(proof), err
	}))
	if err != nil {
		t.Fatal(err)
	}
	cells := make([]commitment.Cell, MaxValues)
	root, err := cpu.Commit(cells)
	if err != nil {
		t.Fatal(err)
	}
	acceleratedRoot, err := accelerated.Commit(cells)
	if err != nil {
		t.Fatal(err)
	}
	if !acceleratedRoot.Equals(root) {
		t.Fatal("accelerated empty-cell root differs from CPU root")
	}
	prepared, err := accelerated.PrepareOpening(root, cells)
	if err != nil {
		t.Fatal(err)
	}
	value, proof, err := prepared.Open(MaxValues - 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(value) != 0 {
		t.Fatalf("empty opening returned %x", value)
	}
	if ok, err := cpu.VerifyIndex(root, MaxValues-1, value, proof); err != nil || !ok {
		t.Fatalf("CPU verification = %v, %v; want true, nil", ok, err)
	}
}

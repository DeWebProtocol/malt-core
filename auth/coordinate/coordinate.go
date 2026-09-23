// Package coordinate defines authentication positions independently of application labels.
package coordinate

import (
	"encoding/binary"
	"errors"
)

type Kind string

const (
	Key   Kind = "key"
	Index Kind = "index"
)

// Coordinate is a sparse key or a dense sequence index. Exactly one is active.
type Coordinate struct {
	Kind  Kind
	Index uint64
	Key   [32]byte
}

func At(index uint64) Coordinate { return Coordinate{Kind: Index, Index: index} }

// EncodeIndex returns the canonical eight-byte, unsigned big-endian index.
func EncodeIndex(index uint64) []byte {
	return binary.BigEndian.AppendUint64(make([]byte, 0, 8), index)
}

// EncodeKey returns an owned canonical key encoding.
func EncodeKey(key [32]byte) []byte { return append([]byte{}, key[:]...) }

// Parse accepts only canonical coordinate encodings. The caller checks that the
// resulting kind is supported by its selected layout.
func Parse(encoded []byte) (Coordinate, error) {
	switch len(encoded) {
	case 8:
		return At(binary.BigEndian.Uint64(encoded)), nil
	case 32:
		return Coordinate{Kind: Key, Key: [32]byte(encoded)}, nil
	default:
		return Coordinate{}, errors.New("coordinate must contain exactly 8 index bytes or 32 key bytes")
	}
}
func (c Coordinate) Validate() error {
	if c.Kind == Index && c.Key == ([32]byte{}) || c.Kind == Key && c.Index == 0 {
		return nil
	}
	return errors.New("noncanonical coordinate")
}
func (c Coordinate) Encode() ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if c.Kind == Index {
		return EncodeIndex(c.Index), nil
	}
	return EncodeKey(c.Key), nil
}

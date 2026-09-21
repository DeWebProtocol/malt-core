package commitment

import "bytes"

// Cell is the opaque, canonically encoded value authenticated at one index.
// Semantic layers decide how to encode their state into cells; primitive
// backends only authenticate the resulting bytes.
type Cell []byte

// NewCell clones raw bytes into a new commitment cell.
func NewCell(data []byte) Cell {
	if len(data) == 0 {
		return nil
	}
	out := make([]byte, len(data))
	copy(out, data)
	return Cell(out)
}

// Bytes returns a cloned byte slice for the cell.
func (c Cell) Bytes() []byte {
	return NewCell(c)
}

// Equal compares two cells.
func (c Cell) Equal(other Cell) bool {
	return bytes.Equal(c, other)
}

// Defined reports whether the cell carries any bytes.
func (c Cell) Defined() bool {
	return len(c) > 0
}

// CloneCells deep-copies a cell slice.
func CloneCells(values []Cell) []Cell {
	if values == nil {
		return nil
	}
	out := make([]Cell, len(values))
	for i, value := range values {
		out[i] = NewCell(value)
	}
	return out
}

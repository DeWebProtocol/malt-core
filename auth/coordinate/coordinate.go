// Package coordinate defines authentication positions independently of application inputs.
package coordinate

type Kind string

const (
	Key   Kind = "key"
	Index Kind = "index"
)

// Value is a sparse key or a dense sequence index. Exactly one is active.
type Value struct {
	Kind  Kind
	Index uint64
	Key   [32]byte
}

func At(index uint64) Value { return Value{Kind: Index, Index: index} }

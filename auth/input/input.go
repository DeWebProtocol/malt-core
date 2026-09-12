// Package input interprets caller inputs before authentication layout routing.
// Rules operate on explicit inputs, never on filesystem paths or ambient state.
package input

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"unicode/utf8"
)

type ID uint8

const (
	Direct           ID = 0
	BytesSHA256      ID = 1
	UnixFSNameSHA256 ID = 2
)

type Kind string

const (
	Index   Kind   = "index"
	Key     Kind   = "key"
	Label   Kind   = "label"
	System  Kind   = "system"
	Payload uint64 = 1
)

// Value has exactly one active field. Data is opaque application/key bytes;
// Number is an index or a registered system selector. Constructors copy bytes.
type Value struct {
	Kind   Kind   `json:"kind"`
	Data   []byte `json:"data,omitempty"`
	Number uint64 `json:"number,omitempty"`
}

func LabelValue(data []byte) Value      { return Value{Kind: Label, Data: bytes.Clone(data)} }
func KeyValue(key [32]byte) Value       { return Value{Kind: Key, Data: bytes.Clone(key[:])} }
func IndexValue(index uint64) Value     { return Value{Kind: Index, Number: index} }
func SystemValue(selector uint64) Value { return Value{Kind: System, Number: selector} }

func (v Value) Validate() error {
	switch v.Kind {
	case Key:
		if len(v.Data) != 32 || v.Number != 0 {
			return errors.New("native keys must contain exactly 32 bytes")
		}
	case Label:
		if v.Number != 0 {
			return errors.New("labels cannot carry an index")
		}
	case Index, System:
		if len(v.Data) != 0 {
			return errors.New("numeric inputs cannot carry data")
		}
	default:
		return fmt.Errorf("unknown input kind %q", v.Kind)
	}
	return nil
}

// Coordinate separates sequence indices from Prefix keys. It is the only
// input interpreted by a layout; labels never reach Prefix routing.
type Coordinate struct {
	Kind  Kind
	Index uint64
	Key   [32]byte
}

// Rule is a deterministic input-to-coordinate function. A registered ID fixes
// its full behavior, including validation, normalization and namespace rules.
type Rule interface {
	Derive(Value) (Coordinate, error)
}
type RuleFunc func(Value) (Coordinate, error)

func (f RuleFunc) Derive(v Value) (Coordinate, error) { return f(v) }

type Registry struct {
	mu    sync.RWMutex
	rules map[ID]Rule
}

func NewRegistry() *Registry { return &Registry{rules: make(map[ID]Rule)} }
func (r *Registry) Register(id ID, rule Rule) error {
	if r == nil || rule == nil || isNilRule(rule) {
		return errors.New("input registry and rule are required")
	}
	if id <= UnixFSNameSHA256 {
		return fmt.Errorf("built-in input rule %d is reserved; use DefaultRegistry", id)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.rules == nil {
		r.rules = make(map[ID]Rule)
	}
	if _, exists := r.rules[id]; exists {
		return fmt.Errorf("input rule %d is already registered", id)
	}
	r.rules[id] = rule
	return nil
}
func (r *Registry) Derive(id ID, value Value) (Coordinate, error) {
	if err := value.Validate(); err != nil {
		return Coordinate{}, err
	}
	if r == nil {
		return Coordinate{}, errors.New("input registry is nil")
	}
	r.mu.RLock()
	rule := r.rules[id]
	r.mu.RUnlock()
	if rule == nil {
		return Coordinate{}, fmt.Errorf("unsupported input rule %d", id)
	}
	value.Data = bytes.Clone(value.Data)
	coordinate, err := rule.Derive(value)
	if err != nil {
		return Coordinate{}, err
	}
	if coordinate.Kind != Index && coordinate.Kind != Key {
		return Coordinate{}, errors.New("rule returned an invalid coordinate kind")
	}
	if coordinate.Kind == Key && coordinate.Index != 0 || coordinate.Kind == Index && coordinate.Key != ([32]byte{}) {
		return Coordinate{}, errors.New("rule returned a noncanonical coordinate")
	}
	return coordinate, nil
}

// DefaultRegistry returns a new independent registry. Registration never
// changes the behavior of another client, service, or verifier instance.
func DefaultRegistry() *Registry {
	return &Registry{rules: map[ID]Rule{Direct: RuleFunc(direct), BytesSHA256: RuleFunc(labelHash), UnixFSNameSHA256: RuleFunc(unixFSName)}}
}

func direct(v Value) (Coordinate, error) {
	switch v.Kind {
	case Index:
		return Coordinate{Kind: Index, Index: v.Number}, nil
	case Key:
		return Coordinate{Kind: Key, Key: [32]byte(v.Data)}, nil
	default:
		return Coordinate{}, errors.New("direct input requires an index or a native key")
	}
}

func labelHash(v Value) (Coordinate, error) {
	encoded := []byte("malt:selector:sha256:0\x00")
	switch v.Kind {
	case Label:
		encoded = append(encoded, 0)
		encoded = binary.AppendUvarint(encoded, uint64(len(v.Data)))
		encoded = append(encoded, v.Data...)
	case System:
		if v.Number != Payload {
			return Coordinate{}, fmt.Errorf("unsupported system selector %d", v.Number)
		}
		encoded = append(encoded, 1)
		encoded = binary.AppendUvarint(encoded, v.Number)
	default:
		return Coordinate{}, errors.New("label rule requires a label or system selector")
	}
	return Coordinate{Kind: Key, Key: sha256.Sum256(encoded)}, nil
}

// unixFSName interprets ONE directory-entry name, not a path. MALT's named
// rule accepts valid nonempty UTF-8 and rejects slash, NUL, dot and dot-dot.
// It does not normalize Unicode, fold case, percent-decode, or follow links.
func unixFSName(v Value) (Coordinate, error) {
	if v.Kind == Label {
		if len(v.Data) == 0 || !utf8.Valid(v.Data) || bytes.ContainsAny(v.Data, "/\x00") || bytes.Equal(v.Data, []byte(".")) || bytes.Equal(v.Data, []byte("..")) {
			return Coordinate{}, errors.New("invalid UnixFS directory-entry name")
		}
	}
	return labelHash(v)
}

func isNilRule(rule Rule) bool {
	v := reflect.ValueOf(rule)
	switch v.Kind() {
	case reflect.Ptr, reflect.Func, reflect.Interface, reflect.Map, reflect.Slice, reflect.Chan:
		return v.IsNil()
	}
	return false
}
func (r *Registry) Supports(id ID) bool {
	if r == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.rules[id] != nil
}

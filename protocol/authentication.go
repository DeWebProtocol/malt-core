package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"

	"github.com/dewebprotocol/malt-core/auth/engine"
	"github.com/dewebprotocol/malt-core/auth/input"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

const AuthenticationProfile = "malt.authentication/0"

// AuthenticationPathProfile authenticates early traversal absence without
// changing Root encoding or the complete candidate profile.
const AuthenticationPathProfile = "malt.authentication/1"

// AuthenticationRequest uses explicit steps. Every visited Root chooses its
// own AA; the protocol assigns no path separator or application normalization.
type AuthenticationRequest struct {
	Profile   string        `json:"profile"`
	Root      string        `json:"root"`
	Steps     []input.Value `json:"steps"`
	Operation string        `json:"operation"`
	Input     *input.Value  `json:"input,omitempty"`
	Start     *uint64       `json:"start,omitempty,string"`
	End       *uint64       `json:"end,omitempty,string"`
}

func (q AuthenticationRequest) Validate() error {
	if q.Profile != AuthenticationProfile && q.Profile != AuthenticationPathProfile {
		return errors.New("unsupported authentication profile")
	}
	root, err := cid.Decode(q.Root)
	if err != nil {
		return err
	}
	if _, _, err := maltcid.ParseRoot(root); err != nil {
		return err
	}
	if len(q.Steps) > 256 {
		return errors.New("too many traversal steps")
	}
	for _, step := range q.Steps {
		if err := step.Validate(); err != nil {
			return err
		}
	}
	switch q.Operation {
	case "resolve":
		if q.Input != nil || q.Start != nil || q.End != nil {
			return errors.New("resolve carries a primitive query")
		}
	case "binding":
		if q.Input == nil || q.Start != nil || q.End != nil {
			return errors.New("binding requires only input")
		}
		return q.Input.Validate()
	case "range":
		if q.Input != nil || q.Start == nil {
			return errors.New("range requires start and optional end")
		}
		if q.End != nil && *q.End < *q.Start {
			return errors.New("inverted byte range")
		}
	default:
		return errors.New("unknown authentication operation")
	}
	return nil
}

type AuthenticationResult struct {
	AbsentStep *uint64             `json:"absent_step,omitempty,string"`
	Profile    string              `json:"profile"`
	Resolved   string              `json:"resolved"`
	Traversal  engine.Traversal    `json:"traversal"`
	Binding    *engine.Result      `json:"binding,omitempty"`
	Range      *engine.RangeResult `json:"range,omitempty"`
}
type AuthenticationVerification struct {
	Request AuthenticationRequest `json:"request"`
	Result  AuthenticationResult  `json:"result"`
}

// AuthenticationCandidate contains a client-computed Root and complete input
// view/materialization. It proves bindings, not update authorization, content
// availability, publication, freshness, or client acceptance.
type AuthenticationCandidate struct {
	Previous string               `json:"previous,omitempty"`
	Profile  string               `json:"profile"`
	Root     string               `json:"root"`
	State    engine.State         `json:"state"`
	Nodes    []AuthenticationNode `json:"nodes"`
}
type AuthenticationNode struct {
	Reference []byte   `json:"reference"`
	Cells     [][]byte `json:"cells"`
}

func DecodeAuthenticationRequest(data []byte) (AuthenticationRequest, error) {
	var v AuthenticationRequest
	if err := decodeAuthenticationJSON(data, &v); err != nil {
		return v, err
	}
	return v, v.Validate()
}
func DecodeAuthenticationResult(data []byte) (AuthenticationResult, error) {
	var v AuthenticationResult
	err := decodeAuthenticationJSON(data, &v)
	return v, err
}
func DecodeAuthenticationVerification(data []byte) (AuthenticationVerification, error) {
	var v AuthenticationVerification
	if err := decodeAuthenticationJSON(data, &v); err != nil {
		return v, err
	}
	return v, v.Request.Validate()
}
func DecodeAuthenticationCandidate(data []byte) (AuthenticationCandidate, error) {
	var v AuthenticationCandidate
	if err := decodeAuthenticationJSON(data, &v); err != nil {
		return v, err
	}
	return v, v.Validate()
}

func decodeAuthenticationJSON(data []byte, target any) error {
	if len(data) == 0 || len(data) > MaxVerificationJSONBytes {
		return errors.New("authentication JSON size is outside bounds")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := uniqueJSON(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("trailing authentication JSON")
	}
	if err := exactAuthenticationFields(data, reflect.TypeOf(target)); err != nil {
		return err
	}
	return decodeVerificationJSON(data, target)
}
func uniqueJSON(d *json.Decoder, depth int) error {
	if depth > 256 {
		return errors.New("JSON nesting exceeds limit")
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]bool)
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return fmt.Errorf("invalid or duplicate JSON field %v", key)
			}
			seen[name] = true
			if err := uniqueJSON(d, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := uniqueJSON(d, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	_, err = d.Token()
	return err
}

func (c AuthenticationCandidate) Validate() error {
	if c.Profile != AuthenticationProfile {
		return errors.New("unsupported candidate profile")
	}
	root, err := cid.Decode(c.Root)
	if err != nil {
		return err
	}
	d, _, err := maltcid.ParseRoot(root)
	if err != nil {
		return err
	}
	if d != c.State.Descriptor {
		return errors.New("candidate state descriptor differs from Root")
	}
	if c.Previous != "" {
		previous, err := cid.Decode(c.Previous)
		if err != nil {
			return err
		}
		if _, _, err := maltcid.ParseRoot(previous); err != nil {
			return err
		}
	}
	for _, entry := range c.State.Entries {
		if err := entry.Input.Validate(); err != nil {
			return err
		}
		if !entry.Target.Defined() {
			return errors.New("undefined candidate target")
		}
	}
	return nil
}

func DecodeAuthenticationState(data []byte) (engine.State, error) {
	var state engine.State
	if err := decodeAuthenticationJSON(data, &state); err != nil {
		return state, err
	}
	if err := state.Descriptor.Validate(); err != nil {
		return state, err
	}
	for _, entry := range state.Entries {
		if err := entry.Input.Validate(); err != nil {
			return state, err
		}
		if !entry.Target.Defined() {
			return state, errors.New("undefined state target")
		}
	}
	return state, nil
}

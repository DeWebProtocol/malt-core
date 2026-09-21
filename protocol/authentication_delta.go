package protocol

import (
	"errors"
	"fmt"

	"github.com/dewebprotocol/malt-core/auth/engine"
	"github.com/dewebprotocol/malt-core/auth/input"
	cid "github.com/ipfs/go-cid"
)

const AuthenticationDeltaProfile = "malt.authentication-delta/0"

const MaxAuthenticationChanges = 1 << 20

// AuthenticationDelta carries typed changes for a retained complete writer.
// It is neither a base-state witness nor a state-transition proof.
type AuthenticationDelta struct {
	Profile   string                 `json:"profile"`
	Changes   []AuthenticationChange `json:"changes"`
	Count     *uint64                `json:"count,omitempty,string"`
	TotalSize *uint64                `json:"total_size,omitempty,string"`
}
type AuthenticationChange struct {
	Input  input.Value `json:"input"`
	Before *string     `json:"before,omitempty"`
	After  *string     `json:"after,omitempty"`
}

func DecodeAuthenticationDelta(data []byte) (AuthenticationDelta, error) {
	var d AuthenticationDelta
	if err := decodeAuthenticationJSON(data, &d); err != nil {
		return d, err
	}
	_, err := d.CoreChanges()
	return d, err
}
func (d AuthenticationDelta) CoreChanges() ([]engine.Change, error) {
	if d.Profile != AuthenticationDeltaProfile || d.Changes == nil {
		return nil, errors.New("invalid authentication delta profile or changes")
	}
	if len(d.Changes) > MaxAuthenticationChanges {
		return nil, errors.New("too many authentication changes")
	}
	changes := make([]engine.Change, len(d.Changes))
	for i, c := range d.Changes {
		if err := c.Input.Validate(); err != nil {
			return nil, err
		}
		if c.Before == nil && c.After == nil {
			return nil, errors.New("empty authentication change")
		}
		changes[i].Input = c.Input
		for j, raw := range []*string{c.Before, c.After} {
			if raw == nil {
				continue
			}
			value, err := cid.Decode(*raw)
			if err != nil {
				return nil, fmt.Errorf("change %d target: %w", i, err)
			}
			if j == 0 {
				changes[i].Before = value
			} else {
				changes[i].After = value
			}
		}
	}
	return changes, nil
}

package protocol

import (
	"errors"
	"fmt"

	"github.com/dewebprotocol/malt-core/engine"
	cid "github.com/ipfs/go-cid"
)

const AuthenticationDeltaProfile = "malt.authentication-delta/2"

const MaxAuthenticationChanges = 1 << 20

// AuthenticationDelta carries typed changes for a retained complete writer.
// It is neither a base-state witness nor a state-transition proof.
type AuthenticationDelta struct {
	Profile string                 `json:"profile"`
	Changes []AuthenticationChange `json:"changes"`
	Count   *uint64                `json:"count,omitempty,string"`
	// Absent preserves the payload; the empty string explicitly removes it.
	PayloadCID *string `json:"payload_cid,omitempty"`
}
type AuthenticationChange struct {
	Label  []byte  `json:"label"`
	Before *string `json:"before,omitempty"`
	After  *string `json:"after,omitempty"`
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
	if _, err := d.CorePayloadCID(); err != nil {
		return nil, err
	}
	changes := make([]engine.Change, len(d.Changes))
	for i, c := range d.Changes {
		if c.Label == nil {
			return nil, errors.New("label is required")
		}
		if c.Before == nil && c.After == nil {
			return nil, errors.New("empty authentication change")
		}
		changes[i].Label = c.Label
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

func (d AuthenticationDelta) CorePayloadCID() (*cid.Cid, error) {
	if d.PayloadCID == nil {
		return nil, nil
	}
	value := cid.Undef
	if *d.PayloadCID != "" {
		var err error
		value, err = cid.Decode(*d.PayloadCID)
		if err != nil {
			return nil, fmt.Errorf("payload CID: %w", err)
		}
	}
	return &value, nil
}

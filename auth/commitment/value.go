package commitment

import (
	"encoding/hex"
	"fmt"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
)

// Value is an immutable, profile-qualified primitive commitment. It is not an
// application Root or a CID; layouts and input rules belong to the Root layer.
// Its zero value is undefined. Construction validates the exact profile width.
type Value struct{ encoded string }

var Undef Value

func NewValue(profile maltcid.ProfileID, data []byte) (Value, error) {
	encoded, err := maltcid.Multicommitment(profile, data)
	if err != nil {
		return Undef, err
	}
	return Value{encoded: string(encoded)}, nil
}
func ParseValue(encoded []byte) (Value, error) {
	profile, data, err := maltcid.ParseMulticommitment(encoded)
	if err != nil {
		return Undef, err
	}
	return NewValue(profile, data)
}
func (v Value) Defined() bool           { return v.encoded != "" }
func (v Value) Equals(other Value) bool { return v == other }
func (v Value) Bytes() []byte           { return []byte(v.encoded) }
func (v Value) String() string          { return hex.EncodeToString(v.Bytes()) }
func (v Value) ProfileID() maltcid.ProfileID {
	id, _, _ := maltcid.ParseMulticommitment(v.Bytes())
	return id
}
func (v Value) CommitmentBytes(profile maltcid.ProfileID) ([]byte, error) {
	id, data, err := maltcid.ParseMulticommitment(v.Bytes())
	if err != nil {
		return nil, err
	}
	if id != profile {
		return nil, fmt.Errorf("commitment profile %d does not match %d", id, profile)
	}
	return data, nil
}

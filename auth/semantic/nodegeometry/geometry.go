// Package nodegeometry exposes the current profile widths to materialization adapters.
package nodegeometry

import (
	"fmt"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
)

const (
	IPANodeWidth = 256
	KZGNodeWidth = 4096
)

type Geometry struct{ nodeWidth int }

func ForBackend(kind maltcid.BackendKind) (Geometry, error) {
	var id maltcid.ProfileID
	switch kind {
	case maltcid.BackendKindIPA:
		id = maltcid.IPA256
	case maltcid.BackendKindKZG:
		id = maltcid.KZG4096
	default:
		return Geometry{}, fmt.Errorf("unsupported commitment backend %q", kind)
	}
	profile, err := maltcid.Profile(id)
	if err != nil {
		return Geometry{}, err
	}
	return Geometry{nodeWidth: profile.Slots}, nil
}
func (g Geometry) NodeWidth() int { return g.nodeWidth }

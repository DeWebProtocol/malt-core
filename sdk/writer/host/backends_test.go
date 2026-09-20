package host

import (
	"fmt"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
	"github.com/dewebprotocol/malt-core/auth/commitment/kzg"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
)

func newComputer(backend string) (*Computer, error) {
	var scheme commitment.IndexCommitment
	var err error
	switch maltcid.BackendKind(backend) {
	case maltcid.BackendKindKZG:
		scheme, err = kzg.NewScheme()
	case maltcid.BackendKindIPA:
		scheme, err = ipa.NewCommitterScheme(ipa.ProfileDirect)
	default:
		return nil, fmt.Errorf("unsupported backend %q", backend)
	}
	if err != nil {
		return nil, err
	}
	return NewComputer(map[maltcid.BackendKind]commitment.IndexCommitment{maltcid.BackendKind(backend): scheme})
}

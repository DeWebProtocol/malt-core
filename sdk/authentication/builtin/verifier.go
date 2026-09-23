// Package builtin provides the opt-in built-in verification profiles for the
// authentication SDK. It imports both commitment backends; writers should use
// sdk/authentication with an injected engine instead.
package builtin

import (
	"fmt"

	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
	"github.com/dewebprotocol/malt-core/auth/commitment/kzg"
	"github.com/dewebprotocol/malt-core/engine"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
)

// NewVerifier installs exact verification-only profiles. With no arguments it
// installs both built-in VC profiles. It performs no network lookup or mutable
// resolution.
func NewVerifier(profiles ...maltcid.ProfileID) (*engine.Engine, error) {
	if len(profiles) == 0 {
		profiles = []maltcid.ProfileID{maltcid.KZG4096, maltcid.IPA256}
	}
	registry := engine.NewRegistry()
	for _, id := range profiles {
		var scheme engine.Profile
		var err error
		switch id {
		case maltcid.KZG4096:
			scheme, err = kzg.NewVerifierScheme()
		case maltcid.IPA256:
			scheme, err = ipa.NewVerifierScheme()
		default:
			return nil, fmt.Errorf("unsupported verification profile %d", id)
		}
		if err != nil {
			return nil, err
		}
		if err := registry.Register(scheme); err != nil {
			return nil, err
		}
	}
	return engine.New(registry), nil
}

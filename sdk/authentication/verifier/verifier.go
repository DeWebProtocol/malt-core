// Package verifier provides the opt-in built-in verification profiles for the
// authentication SDK. It imports both commitment backends; writers should use
// sdk/authentication with an injected engine instead.
package verifier

import (
	"fmt"

	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
	"github.com/dewebprotocol/malt-core/auth/commitment/kzg"
	"github.com/dewebprotocol/malt-core/auth/engine"
	"github.com/dewebprotocol/malt-core/auth/input"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
)

// New installs exact verification-only profiles and the given input
// registry. Nil rules selects the built-in rules. No profiles means both
// built-in VC profiles. It performs no network lookup or mutable resolution.
func New(rules *input.Registry, profiles ...maltcid.ProfileID) (*engine.Engine, error) {
	if rules == nil {
		rules = input.DefaultRegistry()
	}
	if len(profiles) == 0 {
		profiles = []maltcid.ProfileID{maltcid.KZG4096, maltcid.IPA256}
	}
	registry := engine.NewRegistry()
	for _, id := range profiles {
		var scheme engine.ProfileVerifier
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
	return engine.New(rules, registry), nil
}

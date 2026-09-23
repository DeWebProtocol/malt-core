// Package host exposes bounded typed authentication operations to native and
// WASM hosts. Persistence, publication and trust remain caller-owned.
package host

import (
	"fmt"

	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/engine"
	"github.com/dewebprotocol/malt-core/sdk/authentication"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
)

type Computer struct {
	authEngine  *engine.Engine
	authSession *authentication.Session
}

func NewComputer(schemes map[maltcid.BackendKind]commitment.Backend) (*Computer, error) {
	if len(schemes) == 0 {
		return nil, fmt.Errorf("writer backends are required")
	}
	profiles := engine.NewRegistry()
	for kind, scheme := range schemes {
		profile, ok := scheme.(engine.Profile)
		if !ok {
			return nil, fmt.Errorf("writer backend must expose an exact VC profile")
		}
		if err := profiles.Register(profile); err != nil {
			return nil, err
		}
		config, err := maltcid.Profile(profile.ProfileID())
		if err != nil {
			return nil, err
		}
		if config.Algorithm != kind {
			return nil, fmt.Errorf("writer backend key differs from its profile")
		}
	}
	e := engine.New(profiles)
	session, err := authentication.NewSession(e, authentication.SessionLimits{})
	if err != nil {
		return nil, err
	}
	return &Computer{authEngine: e, authSession: session}, nil
}

//go:build !writer_kzg && !writer_ipa

package main

import (
	"fmt"
	"os"

	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
	"github.com/dewebprotocol/malt-core/auth/commitment/kzg"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
)

func startupBackend() (string, error) {
	return parseStartupBackend(os.Args[1:])
}

func startupProfile(backend string) string {
	if backend == string(maltcid.BackendKindIPA) {
		return string(ipa.ProfileFast)
	}
	return ""
}

func newComputer(backend string) (*computer, error) {
	var (
		kind   maltcid.BackendKind
		scheme commitment.IndexCommitment
		err    error
	)
	switch backend {
	case string(maltcid.BackendKindKZG):
		kind = maltcid.BackendKindKZG
		scheme, err = kzg.NewScheme()
		if err != nil {
			return nil, fmt.Errorf("initialize KZG writer: %w", err)
		}
	case string(maltcid.BackendKindIPA):
		kind = maltcid.BackendKindIPA
		scheme, err = ipa.NewCommitterScheme(ipa.ProfileFast)
		if err != nil {
			return nil, fmt.Errorf("initialize IPA writer: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported writer backend %q", backend)
	}
	return &computer{schemes: map[maltcid.BackendKind]commitment.IndexCommitment{
		kind: scheme,
	}}, nil
}

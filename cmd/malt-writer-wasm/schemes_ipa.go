//go:build writer_ipa && !writer_kzg

package main

import (
	"fmt"
	writerhost "github.com/dewebprotocol/malt-core/sdk/writer/host"

	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
)

// ipaCommitterProfile is fixed independently in each release artifact with
// -ldflags=-X=main.ipaCommitterProfile={direct|compact|fast}.
var ipaCommitterProfile = string(ipa.ProfileFast)

func startupBackend() (string, error) {
	return string(maltcid.BackendKindIPA), nil
}

func startupProfile(string) string { return ipaCommitterProfile }

func newComputer(backend string) (*writerhost.Computer, error) {
	if backend != string(maltcid.BackendKindIPA) {
		return nil, fmt.Errorf("IPA writer does not support backend %q", backend)
	}
	profile := ipa.CommitterProfile(ipaCommitterProfile)
	scheme, err := ipa.NewCommitterScheme(profile)
	if err != nil {
		return nil, fmt.Errorf("initialize IPA %s writer: %w", profile, err)
	}
	return writerhost.NewComputer(map[maltcid.BackendKind]commitment.IndexCommitment{
		maltcid.BackendKindIPA: scheme,
	})
}

package verifier_test

import (
	"testing"

	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
	"github.com/dewebprotocol/malt-core/auth/commitment/kzg"
	authverifier "github.com/dewebprotocol/malt-core/auth/verifier"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
)

func TestBackendRegistryRejectsMismatchedSchemeGeometry(t *testing.T) {
	t.Parallel()

	ipaScheme, err := ipa.NewScheme()
	if err != nil {
		t.Fatalf("ipa.NewScheme: %v", err)
	}
	kzgScheme, err := kzg.NewScheme()
	if err != nil {
		t.Fatalf("kzg.NewScheme: %v", err)
	}

	tests := []struct {
		name   string
		kind   maltcid.BackendKind
		scheme commitment.IndexVerifier
	}{
		{name: "kzg_kind_with_ipa_scheme", kind: maltcid.BackendKindKZG, scheme: ipaScheme},
		{name: "ipa_kind_with_kzg_scheme", kind: maltcid.BackendKindIPA, scheme: kzgScheme},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			registry := authverifier.NewBackendRegistry()
			if err := registry.RegisterScheme(test.kind, test.scheme); err == nil {
				t.Fatal("RegisterScheme accepted mismatched backend geometry")
			}
		})
	}
}

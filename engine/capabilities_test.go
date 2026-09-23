package engine_test

import (
	"testing"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
	"github.com/dewebprotocol/malt-core/auth/commitment/kzg"
	"github.com/dewebprotocol/malt-core/derivation"
	"github.com/dewebprotocol/malt-core/engine"
	"github.com/dewebprotocol/malt-core/sdk/authentication"
	"github.com/dewebprotocol/malt-core/sdk/authentication/builtin"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
)

type commitProfile struct {
	commitment.Committer
	id maltcid.ProfileID
}

func (p commitProfile) ProfileID() maltcid.ProfileID { return p.id }

type proofProfile struct {
	commitment.Prover
	commitment.Verifier
	id maltcid.ProfileID
}

func (p proofProfile) ProfileID() maltcid.ProfileID { return p.id }
func (p proofProfile) MaxValues() int               { return p.Prover.MaxValues() }

func capabilityEngine(t *testing.T, p engine.Profile) *engine.Engine {
	t.Helper()
	registry := engine.NewRegistry()
	if err := registry.Register(p); err != nil {
		t.Fatal(err)
	}
	return engine.New(registry)
}

// Every operation must work with its own capabilities rather than requiring
// a full backend. In particular, serving a proof cannot silently recommit.
func TestIndependentAuthenticationCapabilities(t *testing.T) {
	for _, id := range []maltcid.ProfileID{maltcid.KZG4096, maltcid.IPA256} {
		t.Run(idName(id), func(t *testing.T) {
			var backend commitment.Backend
			var err error
			if id == maltcid.KZG4096 {
				backend, err = kzg.NewScheme()
			} else {
				backend, err = ipa.NewCommitterScheme(ipa.ProfileDirect)
			}
			if err != nil {
				t.Fatal(err)
			}
			committer := capabilityEngine(t, commitProfile{Committer: backend, id: id})
			prover := capabilityEngine(t, proofProfile{Prover: backend, Verifier: backend, id: id})
			verifier, err := builtin.NewVerifier(id)
			if err != nil {
				t.Fatal(err)
			}
			query := []byte("a/b")
			state := engine.State{Descriptor: maltcid.RootDescriptor{Layout: maltcid.Prefix, DerivationProfile: uint8(derivation.SHA256), Profile: id}, Entries: []engine.Entry{{Label: query, Target: target("before")}}}
			nodes := memory.NewNodes()
			root, err := committer.Build(t.Context(), state, nodes)
			if err != nil {
				t.Fatal(err)
			}
			proof, err := prover.Prove(t.Context(), root, query, nodes)
			if err != nil {
				t.Fatal(err)
			}
			if valid, err := verifier.Verify(root, query, proof); err != nil || !valid {
				t.Fatalf("independent verification: %v, %v", valid, err)
			}
			if _, err := prover.Build(t.Context(), state, nodes); err == nil {
				t.Fatal("proof-only profile can compute commitments")
			}
			if _, err := committer.Prove(t.Context(), root, query, nodes); err == nil {
				t.Fatal("commit-only profile can generate proofs")
			}
			if _, err := verifier.Prove(t.Context(), root, query, nodes); err == nil {
				t.Fatal("verification-only profile can generate proofs")
			}
			if _, err := prover.Prove(t.Context(), root, query, corruptVector{nodes}); err == nil {
				t.Fatal("proof-only execution accepted inconsistent materialization")
			}
			proof.Target = target("tampered")
			if valid, _ := verifier.Verify(root, query, proof); valid {
				t.Fatal("verification accepted a tampered target")
			}

			// Owned retained nodes allow build/update without generating proofs.
			writer, err := authentication.BuildWriter(t.Context(), committer, state)
			if err != nil {
				t.Fatal(err)
			}
			state.Entries[0].Target = target("after")
			updated, err := writer.Update(t.Context(), state)
			if err != nil {
				t.Fatal(err)
			}
			rebuilt, err := committer.Build(t.Context(), state, memory.NewNodes())
			if err != nil || !updated.Root().Equals(rebuilt) {
				t.Fatalf("commit-only retained update differs from rebuild: %v", err)
			}
		})
	}
}

func idName(id maltcid.ProfileID) string {
	if id == maltcid.KZG4096 {
		return "kzg"
	}
	return "ipa"
}

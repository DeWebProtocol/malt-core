// Command query demonstrates the higher-level serialized SDK query contract.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
	"github.com/dewebprotocol/malt-core/derivation"
	"github.com/dewebprotocol/malt-core/engine"
	"github.com/dewebprotocol/malt-core/maltcid"
	"github.com/dewebprotocol/malt-core/protocol"
	"github.com/dewebprotocol/malt-core/sdk/authentication"
	"github.com/dewebprotocol/malt-core/sdk/authentication/builtin"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx := context.Background()

	// Install a full commitment/proving backend for the local writer and executor.
	// IPA's ProfileDirect controls precomputation, not label derivation.
	scheme, err := ipa.NewCommitterScheme(ipa.ProfileDirect)
	if err != nil {
		return err
	}
	profiles := engine.NewRegistry()
	if err := profiles.Register(scheme); err != nil {
		return err
	}
	prover := engine.New(profiles)

	payload := []byte("A locally verifiable report.")
	cidPrefix := cid.Prefix{Version: 1, Codec: cid.Raw, MhType: mh.SHA2_256, MhLength: -1}
	target, err := cidPrefix.Sum(payload)
	if err != nil {
		return err
	}
	label := []byte("report.txt")
	candidate, err := authentication.Prepare(ctx, prover, engine.State{
		Descriptor: maltcid.RootDescriptor{
			Layout: maltcid.Prefix, DerivationProfile: uint8(derivation.SHA256), Profile: maltcid.IPA256,
		},
		Entries: []engine.Entry{{Label: label, Target: target}},
	})
	if err != nil {
		return err
	}

	// This demo selects the Root it just built locally. A real client must obtain
	// its trusted Root independently of an untrusted query response.
	trustedRoot := candidate.Root
	nodes := memory.NewNodes()
	if err := authentication.Materialize(ctx, prover, candidate, nodes); err != nil {
		return err
	}
	request := protocol.AuthenticationRequest{
		Profile: protocol.AuthenticationPathProfile, Root: trustedRoot,
		Steps: [][]byte{}, Operation: "binding", Label: &label,
	}
	response, err := authentication.Execute(ctx, prover, request, nodes)
	if err != nil {
		return err
	}

	// Simulate a transport boundary. Decode only the result; keep the client's
	// independently constructed request instead of accepting a server's request.
	wire, err := json.Marshal(response)
	if err != nil {
		return err
	}
	result, err := protocol.DecodeAuthenticationResult(wire)
	if err != nil {
		return err
	}
	verifier, err := builtin.NewVerifier(maltcid.IPA256)
	if err != nil {
		return err
	}
	if ok, err := authentication.Verify(verifier, request, result); err != nil || !ok {
		return fmt.Errorf("binding verification: valid=%t, error=%v", ok, err)
	}
	if !result.Binding.Present || !result.Binding.Target.Equals(target) {
		return fmt.Errorf("unexpected binding target")
	}
	fmt.Println("Binding verified: report.txt")

	// Core authenticated the target CID. The application separately checks bytes.
	actual, err := result.Binding.Target.Prefix().Sum(payload)
	if err != nil {
		return err
	}
	if !actual.Equals(result.Binding.Target) {
		return fmt.Errorf("payload does not match authenticated CID")
	}
	fmt.Println("Payload bytes match the authenticated CID")

	missing := []byte("missing.txt")
	missingRequest := request
	missingRequest.Label = &missing
	absence, err := authentication.Execute(ctx, prover, missingRequest, nodes)
	if err != nil {
		return err
	}
	if ok, err := authentication.Verify(verifier, missingRequest, absence); err != nil || !ok {
		return fmt.Errorf("absence verification: valid=%t, error=%v", ok, err)
	}
	if absence.Binding.Present {
		return fmt.Errorf("expected an absent binding")
	}
	fmt.Println("Absence verified: missing.txt")

	wrongTarget, err := cidPrefix.Sum([]byte("Changed report."))
	if err != nil {
		return err
	}
	tampered := result
	changedBinding := *result.Binding
	changedBinding.Target = wrongTarget
	tampered.Binding = &changedBinding
	if ok, err := authentication.Verify(verifier, request, tampered); err == nil && ok {
		return fmt.Errorf("tampered target was accepted")
	}
	fmt.Println("Tampered target rejected")
	return nil
}

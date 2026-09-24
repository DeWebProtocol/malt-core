// Command traversal verifies an explicit chain through two application Roots.
package main

import (
	"context"
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
	scheme, err := ipa.NewCommitterScheme(ipa.ProfileDirect)
	if err != nil {
		return err
	}
	profiles := engine.NewRegistry()
	if err := profiles.Register(scheme); err != nil {
		return err
	}
	prover := engine.New(profiles)
	descriptor := maltcid.RootDescriptor{
		Layout: maltcid.Prefix, DerivationProfile: uint8(derivation.SHA256), Profile: maltcid.IPA256,
	}
	target, err := (cid.Prefix{Version: 1, Codec: cid.Raw, MhType: mh.SHA2_256, MhLength: -1}).Sum([]byte("Report content"))
	if err != nil {
		return err
	}

	// Construct the child before binding its complete Root into the parent.
	child, err := authentication.Prepare(ctx, prover, engine.State{
		Descriptor: descriptor,
		Entries:    []engine.Entry{{Label: []byte("report.txt"), Target: target}},
	})
	if err != nil {
		return err
	}
	childRoot, err := cid.Decode(child.Root)
	if err != nil {
		return err
	}
	parent, err := authentication.Prepare(ctx, prover, engine.State{
		Descriptor: descriptor,
		Entries:    []engine.Entry{{Label: []byte("docs"), Target: childRoot}},
	})
	if err != nil {
		return err
	}

	// The demo supplies both Roots' nodes from one in-memory materializer.
	// ExecuteWithRoots can instead obtain a separate lookup for each reached Root.
	nodes := memory.NewNodes()
	for _, candidate := range []protocol.AuthenticationCandidate{child, parent} {
		if err := authentication.Materialize(ctx, prover, candidate, nodes); err != nil {
			return err
		}
	}

	// The client chooses its locally built parent Root and exact label steps.
	// Core does not split "docs/report.txt" or infer a longest matching label.
	request := protocol.AuthenticationRequest{
		Profile: protocol.AuthenticationPathProfile, Root: parent.Root,
		Steps: [][]byte{[]byte("docs"), []byte("report.txt")}, Operation: "resolve",
	}
	result, err := authentication.Execute(ctx, prover, request, nodes)
	if err != nil {
		return err
	}
	verifier, err := builtin.NewVerifier(maltcid.IPA256)
	if err != nil {
		return err
	}
	if ok, err := authentication.Verify(verifier, request, result); err != nil || !ok {
		return fmt.Errorf("traversal verification: valid=%t, error=%v", ok, err)
	}
	resolved, err := cid.Decode(result.Resolved)
	if err != nil {
		return err
	}
	if !resolved.Equals(target) {
		return fmt.Errorf("unexpected traversal target")
	}
	fmt.Println("Traversal verified: docs -> report.txt -> content CID")

	// A missing step is authenticated early termination. The suffix is not read.
	missingRequest := request
	missingRequest.Steps = [][]byte{[]byte("docs"), []byte("missing.txt"), []byte("unvisited")}
	absence, err := authentication.Execute(ctx, prover, missingRequest, nodes)
	if err != nil {
		return err
	}
	if ok, err := authentication.Verify(verifier, missingRequest, absence); err != nil || !ok {
		return fmt.Errorf("path absence verification: valid=%t, error=%v", ok, err)
	}
	if absence.AbsentStep == nil || *absence.AbsentStep != 1 {
		return fmt.Errorf("expected absence at the second step")
	}
	fmt.Println("Missing second step verified; suffix not evaluated")
	return nil
}

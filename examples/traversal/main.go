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
	"github.com/dewebprotocol/malt-core/sdk/authentication/builtin"
	"github.com/dewebprotocol/malt-core/traversal"
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

	// 1. Commit the child, then bind its complete Root into the parent.
	// Both commits retain their nodes in the same in-memory materializer.
	nodes := memory.NewNodes()
	childView, err := prover.Interpret(engine.State{
		Descriptor: descriptor,
		Entries:    []engine.Entry{{Label: []byte("report.txt"), Target: target}},
	})
	if err != nil {
		return err
	}
	childRoot, err := prover.Commit(ctx, childView, nodes)
	if err != nil {
		return err
	}
	parentView, err := prover.Interpret(engine.State{
		Descriptor: descriptor,
		Entries:    []engine.Entry{{Label: []byte("docs"), Target: childRoot}},
	})
	if err != nil {
		return err
	}
	root, err := prover.Commit(ctx, parentView, nodes)
	if err != nil {
		return err
	}
	fmt.Println("Commit: child and parent Roots created")

	// 2. Prove the selected path. ResolvePath composes binding proofs and
	// returns both the final target and the ordered verification evidence.
	steps := [][]byte{[]byte("docs"), []byte("report.txt")}
	resolved, proof, err := traversal.ResolvePath(ctx, prover, root, steps, nodes)
	if err != nil {
		return err
	}
	fmt.Println("Prove: target and traversal evidence produced")

	// 3. Verify against the client's original Root and exact steps, using a
	// separate verification-only engine with no access to the materializer.
	verifier, err := builtin.NewVerifier(maltcid.IPA256)
	if err != nil {
		return err
	}
	if ok, err := traversal.Verify(verifier, root, steps, resolved, proof); err != nil || !ok {
		return fmt.Errorf("traversal verification: valid=%t, error=%v", ok, err)
	}
	if !resolved.Equals(target) {
		return fmt.Errorf("unexpected traversal target")
	}
	fmt.Println("Verify: docs -> report.txt -> content CID")

	// An additional Prove/Verify pair demonstrates authenticated early absence.
	// Core does not evaluate the suffix after the missing second step.
	missingSteps := [][]byte{[]byte("docs"), []byte("missing.txt"), []byte("unvisited")}
	missingTarget, absence, err := traversal.ResolvePath(ctx, prover, root, missingSteps, nodes)
	if err != nil {
		return err
	}
	if ok, err := traversal.VerifyPath(verifier, root, missingSteps, missingTarget, absence); err != nil || !ok {
		return fmt.Errorf("path absence verification: valid=%t, error=%v", ok, err)
	}
	if missingTarget.Defined() || len(absence.Results) != 2 || absence.Results[1].Present {
		return fmt.Errorf("expected absence at the second step")
	}
	fmt.Println("Missing second step verified; suffix not evaluated")
	return nil
}

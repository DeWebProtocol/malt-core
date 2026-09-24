// Command basic demonstrates Commit, Prove, Update, and Verify.
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

	// Configure an engine that can commit and prove. IPA's ProfileDirect is an
	// execution choice; the labels below use SHA256 coordinate derivation.
	scheme, err := ipa.NewCommitterScheme(ipa.ProfileDirect)
	if err != nil {
		return err
	}
	profiles := engine.NewRegistry()
	if err := profiles.Register(scheme); err != nil {
		return err
	}
	e := engine.New(profiles)

	// 1. Commit: describe the data, derive coordinates, and create its Root.
	// Each entry links a label to a content identifier. Content bytes remain
	// with the application; Commit retains authentication nodes for Prove.
	state := engine.State{
		Descriptor: maltcid.RootDescriptor{
			Layout: maltcid.Prefix, DerivationProfile: uint8(derivation.SHA256), Profile: maltcid.IPA256,
		},
	}
	for _, document := range []struct{ name, content string }{
		{"report.txt", "A locally verifiable report."},
		{"summary.txt", "A short summary."},
	} {
		target, err := (cid.Prefix{Version: 1, Codec: cid.Raw, MhType: mh.SHA2_256, MhLength: -1}).Sum([]byte(document.content))
		if err != nil {
			return err
		}
		state.Entries = append(state.Entries, engine.Entry{Label: []byte(document.name), Target: target})
	}
	view, err := e.Interpret(state)
	if err != nil {
		return err
	}
	nodes := memory.NewNodes()
	root, err := e.Commit(ctx, view, nodes)
	if err != nil {
		return err
	}
	fmt.Printf("Commit: Root = %s\n", root)

	// 2. Prove: use the selected Root and a one-step path to obtain a target
	// and verification evidence. The prover reads the committed nodes.
	label := []byte("report.txt")
	result, err := e.Prove(ctx, root, label, nodes)
	if err != nil {
		return err
	}
	fmt.Printf("Prove: target = %s; evidence ready\n", result.Target)

	// 3. Update: replace the report's target while preserving the original Root.
	// Before comes from the locally committed data, not the unverified result.
	replacement, err := (cid.Prefix{Version: 1, Codec: cid.Raw, MhType: mh.SHA2_256, MhLength: -1}).Sum([]byte("An updated report."))
	if err != nil {
		return err
	}
	updatedRoot, err := e.Apply(ctx, root, []engine.Change{{
		Label: label, Before: state.Entries[0].Target, After: replacement,
	}}, nodes, nodes)
	if err != nil {
		return err
	}
	updatedResult, err := e.Prove(ctx, updatedRoot, label, nodes)
	if err != nil {
		return err
	}
	if updatedRoot.Equals(root) {
		return fmt.Errorf("expected a new Root for the changed report")
	}
	fmt.Println("Update: a new Root created; original Root preserved")

	// 4. Verify: a separate verification-only engine checks the original Root
	// and path against the result. It needs neither state nor nodes.
	// This demo trusts the Root it built locally; a real client selects its
	// trusted Root independently of an untrusted prover's response.
	verifier, err := builtin.NewVerifier(maltcid.IPA256)
	if err != nil {
		return err
	}
	valid, err := verifier.Verify(root, label, result)
	if err != nil {
		return err
	}
	if !valid || !result.Present {
		return fmt.Errorf("invalid original binding")
	}
	updatedValid, err := verifier.Verify(updatedRoot, label, updatedResult)
	if err != nil {
		return err
	}
	if !updatedValid || !updatedResult.Present {
		return fmt.Errorf("invalid updated binding")
	}
	if !result.Target.Equals(state.Entries[0].Target) || !updatedResult.Target.Equals(replacement) {
		return fmt.Errorf("unexpected target at the original or updated Root")
	}
	fmt.Println("Verify: original and updated targets verified")
	return nil
}

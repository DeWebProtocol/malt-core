// Command basic demonstrates Commit, Prove, Update, and Verify with Objects.
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
	"github.com/dewebprotocol/malt-core/engine"
	"github.com/dewebprotocol/malt-core/maltcid"
	"github.com/dewebprotocol/malt-core/sdk/authentication"
	"github.com/dewebprotocol/malt-core/sdk/authentication/builtin"
	"github.com/dewebprotocol/malt-core/sdk/object"
	cid "github.com/ipfs/go-cid"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx := context.Background()
	// Configure an engine for local commitment and proof generation.
	scheme, err := ipa.NewCommitterScheme(ipa.ProfileDirect)
	if err != nil {
		return err
	}
	profiles := engine.NewRegistry()
	if err := profiles.Register(scheme); err != nil {
		return err
	}
	e := engine.New(profiles)

	// 1. Commit: a Map refers to an ordinary immutable content block.
	collection, err := object.NewMap(e, object.MapConfig(maltcid.IPA256))
	if err != nil {
		return err
	}
	content, err := object.NewImmutable([]byte("A locally verifiable report."))
	if err != nil {
		return err
	}
	if err := collection.Set([]byte("report.txt"), content); err != nil {
		return err
	}
	root, err := collection.Commit(ctx)
	if err != nil {
		return err
	}
	fmt.Println("Commit: collection Root created")

	// 2. Prove: collect this version and supply it to the local query store.
	nodes := memory.NewNodes()
	blocks := make(map[string][]byte)
	delta, err := collection.Delta(ctx)
	if err != nil {
		return err
	}
	if err := materialize(ctx, e, nodes, blocks, delta); err != nil {
		return err
	}
	label := []byte("report.txt")
	result, err := e.Prove(ctx, root, label, nodes)
	if err != nil {
		return err
	}
	fmt.Println("Prove: report.txt target and evidence produced")

	// 3. Update: replace the child reference, then commit and collect changes.
	replacement, err := object.NewImmutable([]byte("An updated report."))
	if err != nil {
		return err
	}
	if err := collection.Set(label, replacement); err != nil {
		return err
	}
	updatedRoot, err := collection.Commit(ctx)
	if err != nil {
		return err
	}
	delta, err = collection.Delta(ctx)
	if err != nil {
		return err
	}
	if err := materialize(ctx, e, nodes, blocks, delta); err != nil {
		return err
	}
	updatedResult, err := e.Prove(ctx, updatedRoot, label, nodes)
	if err != nil {
		return err
	}
	fmt.Printf("Update: %d ArcSet and %d new content block collected\n", len(delta.ArcSets), len(delta.Blocks))
	if updatedRoot.Equals(root) {
		return fmt.Errorf("expected a new Root for the changed report")
	}

	// 4. Verify: each result is checked against its independently selected Root.
	// The verifier needs neither the mutable Objects nor the prover's nodes.
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
	if !result.Target.Equals(content.Payload()) || !updatedResult.Target.Equals(replacement.Payload()) {
		return fmt.Errorf("unexpected target at the original or updated Root")
	}
	if valid, err := verifier.Verify(updatedRoot, label, result); err == nil && valid {
		return fmt.Errorf("old evidence was accepted against the updated Root")
	}
	// Fetched content bytes are checked separately against the verified CIDs.
	for _, target := range []cid.Cid{result.Target, updatedResult.Target} {
		data, present := blocks[target.KeyString()]
		actual, err := target.Prefix().Sum(data)
		if err != nil || !present || !actual.Equals(target) {
			return fmt.Errorf("content bytes do not match verified target %s", target)
		}
	}
	fmt.Println("Verify: original and updated targets verified")
	return nil
}

// materialize is example application code: retain content bytes and import
// each collected ArcSet into the caller-owned node store. It performs no I/O.
func materialize(ctx context.Context, e *engine.Engine, nodes *memory.Nodes, blocks map[string][]byte, delta object.Delta) error {
	if len(delta.External) != 0 {
		return fmt.Errorf("example has unresolved external CIDs: %v", delta.External)
	}
	for _, block := range delta.Blocks {
		blocks[block.CID.KeyString()] = block.Bytes
	}
	for _, arcset := range delta.ArcSets {
		candidate, err := arcset.Export(ctx)
		if err != nil {
			return err
		}
		if err := authentication.Materialize(ctx, e, candidate, nodes); err != nil {
			return err
		}
	}
	return nil
}

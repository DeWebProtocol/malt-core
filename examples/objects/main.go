// Command objects commits references recursively, proves a traversal, updates
// a child, and independently verifies both versions.
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
	"github.com/dewebprotocol/malt-core/auth/commitment/kzg"
	"github.com/dewebprotocol/malt-core/auth/coordinate"
	"github.com/dewebprotocol/malt-core/engine"
	"github.com/dewebprotocol/malt-core/maltcid"
	"github.com/dewebprotocol/malt-core/sdk/authentication"
	"github.com/dewebprotocol/malt-core/sdk/authentication/builtin"
	"github.com/dewebprotocol/malt-core/sdk/object"
	"github.com/dewebprotocol/malt-core/traversal"
	cid "github.com/ipfs/go-cid"
)

// Each tagged field is an arc to one child Object. Untagged fields are ignored.
type Document struct {
	*object.Base
	Parts *object.List `malt:"parts"`
}

func (d *Document) Commit(ctx context.Context) (cid.Cid, error) {
	return d.Base.CommitTagged(ctx, d)
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx := context.Background()
	ipaBackend, err := ipa.NewCommitterScheme(ipa.ProfileDirect)
	if err != nil {
		return err
	}
	kzgBackend, err := kzg.NewScheme()
	if err != nil {
		return err
	}
	profiles := engine.NewRegistry()
	if err := profiles.Register(ipaBackend); err != nil {
		return err
	}
	if err := profiles.Register(kzgBackend); err != nil {
		return err
	}
	prover := engine.New(profiles)

	// Commit: construct an ordinary byte leaf and refer to it from parent Objects.
	content, err := object.NewImmutable([]byte("first version"))
	if err != nil {
		return err
	}
	parts, err := object.NewList(prover, object.ListConfig(maltcid.KZG4096))
	if err != nil {
		return err
	}
	if err := parts.Append(content); err != nil {
		return err
	}
	base, err := object.NewBase(prover, object.MapConfig(maltcid.IPA256))
	if err != nil {
		return err
	}
	document := &Document{Base: base, Parts: parts}
	root, err := object.NewMap(prover, object.MapConfig(maltcid.IPA256))
	if err != nil {
		return err
	}
	if err := root.Set([]byte("document"), document); err != nil {
		return err
	}
	trustedRoot, err := root.Commit(ctx) // Commits the entire reachable graph.
	if err != nil {
		return err
	}
	fmt.Println("Committed object graph, children before parents")
	delta, err := root.Delta(ctx)
	if err != nil {
		return err
	}

	// Prove: the root's delta collects every new ArcSet and locally known block.
	// The application chooses where to retain them; Commit performs no I/O.
	nodes := memory.NewNodes()
	blocks := make(map[string][]byte)
	if err := materialize(ctx, prover, nodes, blocks, delta); err != nil {
		return err
	}
	fmt.Printf("Collected %d ArcSets and %d content block\n", len(delta.ArcSets), len(delta.Blocks))
	steps := [][]byte{[]byte("document"), []byte("parts"), coordinate.EncodeIndex(0)}
	target, evidence, err := traversal.ResolvePath(ctx, prover, trustedRoot, steps, nodes)
	if err != nil {
		return err
	}
	fmt.Println("Proved traversal to the content CID")

	// Update: replace a child reference and Commit the root again. The retained
	// ArcSets drive incremental updates; no dirty flag is needed for correctness.
	replacement, err := object.NewImmutable([]byte("second version"))
	if err != nil {
		return err
	}
	if err := parts.Set(0, replacement); err != nil {
		return err
	}
	updatedRoot, err := root.Commit(ctx)
	if err != nil {
		return err
	}
	if updatedRoot.Equals(trustedRoot) {
		return fmt.Errorf("nested update did not change the root")
	}
	delta, err = root.Delta(ctx)
	if err != nil {
		return err
	}
	if err := materialize(ctx, prover, nodes, blocks, delta); err != nil {
		return err
	}
	updatedTarget, updatedEvidence, err := traversal.ResolvePath(ctx, prover, updatedRoot, steps, nodes)
	if err != nil {
		return err
	}
	fmt.Printf("Updated %d ArcSets; collected %d new content block\n", len(delta.ArcSets), len(delta.Blocks))

	// Verify: use only the separately selected Root, path, target and evidence.
	verifier, err := builtin.NewVerifier()
	if err != nil {
		return err
	}
	valid, err := traversal.Verify(verifier, trustedRoot, steps, target, evidence)
	if err != nil || !valid || !target.Equals(content.Payload()) {
		return fmt.Errorf("original traversal: valid=%t, error=%v", valid, err)
	}
	valid, err = traversal.Verify(verifier, updatedRoot, steps, updatedTarget, updatedEvidence)
	if err != nil || !valid || !updatedTarget.Equals(replacement.Payload()) {
		return fmt.Errorf("updated traversal: valid=%t, error=%v", valid, err)
	}
	if valid, err := traversal.Verify(verifier, updatedRoot, steps, target, evidence); err == nil && valid {
		return fmt.Errorf("old evidence was accepted against the updated root")
	}
	for _, target := range []cid.Cid{target, updatedTarget} {
		data, present := blocks[target.KeyString()]
		actual, err := target.Prefix().Sum(data)
		if err != nil || !present || !actual.Equals(target) {
			return fmt.Errorf("content bytes do not match the verified target %s", target)
		}
	}
	fmt.Println("Verified both versions; rejected evidence for the wrong Root")
	return nil
}

func materialize(ctx context.Context, e *engine.Engine, nodes *memory.Nodes, blocks map[string][]byte, delta object.Delta) error {
	if len(delta.External) != 0 {
		return fmt.Errorf("example has unresolved external content: %v", delta.External)
	}
	for _, block := range delta.Blocks {
		blocks[block.CID.KeyString()] = block.Bytes
	}
	for _, arcset := range delta.ArcSets { // Already ordered children before parents.
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

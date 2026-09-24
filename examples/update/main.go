// Command update retains an old Root while verifying an immutable replacement.
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
	cidPrefix := cid.Prefix{Version: 1, Codec: cid.Raw, MhType: mh.SHA2_256, MhLength: -1}
	before, err := cidPrefix.Sum([]byte("Original report"))
	if err != nil {
		return err
	}
	after, err := cidPrefix.Sum([]byte("Revised report"))
	if err != nil {
		return err
	}
	label := []byte("report.txt")
	base, err := authentication.BuildWriter(ctx, prover, engine.State{
		Descriptor: maltcid.RootDescriptor{
			Layout: maltcid.Prefix, DerivationProfile: uint8(derivation.SHA256), Profile: maltcid.IPA256,
		},
		Entries: []engine.Entry{{Label: label, Target: before}},
	})
	if err != nil {
		return err
	}
	originalRoot := base.Root()

	// Apply checks Before and returns a new writer; it does not mutate base.
	next, err := base.Apply(ctx, authentication.Delta{
		Changes: []engine.Change{{Label: label, Before: before, After: after}},
	})
	if err != nil {
		return err
	}
	if !base.Root().Equals(originalRoot) || next.Root().Equals(originalRoot) {
		return fmt.Errorf("expected a distinct new Root and an unchanged base")
	}
	fmt.Println("Original Root preserved; updated Root is distinct")

	verifier, err := builtin.NewVerifier(maltcid.IPA256)
	if err != nil {
		return err
	}
	nodes := memory.NewNodes()
	for _, version := range []struct {
		name   string
		writer *authentication.Writer
		target cid.Cid
	}{
		{"Original", base, before},
		{"Updated", next, after},
	} {
		// Export is an explicit complete candidate, not a partial update witness.
		candidate, err := version.writer.Export(ctx)
		if err != nil {
			return err
		}
		if err := authentication.Materialize(ctx, prover, candidate, nodes); err != nil {
			return err
		}
		request := protocol.AuthenticationRequest{
			Profile: protocol.AuthenticationPathProfile, Root: version.writer.Root().String(),
			Steps: [][]byte{}, Operation: "binding", Label: &label,
		}
		result, err := authentication.Execute(ctx, prover, request, nodes)
		if err != nil {
			return err
		}
		if ok, err := authentication.Verify(verifier, request, result); err != nil || !ok {
			return fmt.Errorf("%s verification: valid=%t, error=%v", version.name, ok, err)
		}
		if !result.Binding.Present || !result.Binding.Target.Equals(version.target) {
			return fmt.Errorf("unexpected %s target", version.name)
		}
		fmt.Printf("%s binding verified\n", version.name)
	}
	// These checks authenticate each selected state independently. They do not
	// prove an authorized transition, publish a Root, or promote client trust.
	return nil
}

package verifier_test

import (
	"context"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/proof/prooflist"
	"github.com/dewebprotocol/malt-core/protocol"
	clientverifier "github.com/dewebprotocol/malt-core/sdk/verifier"
	cid "github.com/ipfs/go-cid"
)

func TestDefaultVerifierAcceptsResolveIdentityContract(t *testing.T) {
	root := "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"
	rootCID, err := cid.Parse(root)
	if err != nil {
		t.Fatal(err)
	}
	local, err := clientverifier.NewDefault()
	if err != nil {
		t.Fatal(err)
	}
	value := protocol.ResolveVerification{
		Request: protocol.ResolveRequest{Profile: protocol.ResolveProfile, Root: root, Segments: []string{}},
		Result: protocol.ResolveResult{
			Profile:   protocol.ResolveProfile,
			Target:    root,
			ProofList: prooflist.ProofList{Root: rootCID, Steps: []prooflist.Step{}},
		},
	}
	if err := local.VerifyResolve(context.Background(), value); err != nil {
		t.Fatalf("VerifyResolve: %v", err)
	}
}

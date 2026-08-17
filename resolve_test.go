package malt_test

import (
	"context"
	"testing"

	malt "github.com/dewebprotocol/malt-core"
	"github.com/dewebprotocol/malt-core/auth/proof/prooflist"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

type acceptingResolveVerifier struct{}

func (acceptingResolveVerifier) VerifyProofList(context.Context, prooflist.ProofList) (bool, error) {
	return true, nil
}

func TestVerifyResolveBindsExplicitPayloadSegment(t *testing.T) {
	root := resolveTestCID(t, "root")
	object := resolveTestCID(t, "object")
	payload := resolveTestCID(t, "payload")
	req := malt.ResolveRequest{Root: root, Segments: []string{"docs", "readme.md", "@payload"}}
	result := malt.ResolveResult{
		Target: payload,
		ProofList: prooflist.ProofList{
			Root: root, Query: "docs/readme.md/@payload",
			Steps: []prooflist.Step{
				{Kind: prooflist.KindMapStep, From: root, Path: "docs/readme.md", Target: object},
				{Kind: prooflist.KindPayloadBinding, From: object, Path: "@payload", Target: payload},
			},
		},
	}
	if err := malt.VerifyResolve(context.Background(), req, result, acceptingResolveVerifier{}); err != nil {
		t.Fatalf("VerifyResolve: %v", err)
	}
	result.ProofList.Query = "docs/readme.md"
	if err := malt.VerifyResolve(context.Background(), req, result, acceptingResolveVerifier{}); err == nil {
		t.Fatal("VerifyResolve accepted a result that omitted the explicit payload segment")
	}
}

func TestVerifyResolveRootIdentityIsStrictlyZeroStep(t *testing.T) {
	root := resolveTestCID(t, "root")
	req := malt.ResolveRequest{Root: root, Segments: []string{}}
	result := malt.ResolveResult{Target: root, ProofList: prooflist.ProofList{Root: root, Steps: []prooflist.Step{}}}
	if err := malt.VerifyResolve(context.Background(), req, result, acceptingResolveVerifier{}); err != nil {
		t.Fatalf("VerifyResolve identity: %v", err)
	}
	result.ProofList.Steps = []prooflist.Step{{Kind: prooflist.KindMapStep, From: root, Path: "hidden", Target: root}}
	if err := malt.VerifyResolve(context.Background(), req, result, acceptingResolveVerifier{}); err == nil {
		t.Fatal("VerifyResolve accepted traversal evidence for root identity")
	}
}

func TestVerifyResolveRejectsPrimitiveReadEvidence(t *testing.T) {
	root := resolveTestCID(t, "root")
	target := resolveTestCID(t, "target")
	index := uint64(0)
	result := malt.ResolveResult{
		Target: target,
		ProofList: prooflist.ProofList{
			Root: root, Query: "item",
			Steps: []prooflist.Step{{Kind: prooflist.KindListIndex, From: root, Index: &index, Target: target, EvidenceKind: "structure", EvidenceBackend: "list"}},
		},
	}
	if err := malt.VerifyResolve(context.Background(), malt.ResolveRequest{Root: root, Segments: []string{"item"}}, result, acceptingResolveVerifier{}); err == nil {
		t.Fatal("VerifyResolve accepted primitive list evidence")
	}
}

func resolveTestCID(t *testing.T, seed string) cid.Cid {
	t.Helper()
	hash, err := mh.Sum([]byte(seed), mh.SHA2_256, -1)
	if err != nil {
		t.Fatal(err)
	}
	return cid.NewCidV1(cid.Raw, hash)
}

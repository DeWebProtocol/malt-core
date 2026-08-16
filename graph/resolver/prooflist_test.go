package resolver

import (
	"bytes"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	"github.com/dewebprotocol/malt-core/auth/proof/evidence"
	"github.com/dewebprotocol/malt-core/auth/proof/prooflist"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

func testCID(t *testing.T, seed string) cid.Cid {
	t.Helper()
	sum, err := mh.Sum([]byte(seed), mh.SHA2_256, -1)
	if err != nil {
		t.Fatalf("mh.Sum failed: %v", err)
	}
	return cid.NewCidV1(cid.Raw, sum)
}

func TestProofListFromTranscriptPreservesOrderPathTargetAndEvidenceKind(t *testing.T) {
	root := testCID(t, "root")
	node := testCID(t, "node")
	payload := testCID(t, "payload")
	transcript := &Transcript{
		Steps: []StepEvidence{
			{
				Path:     arcset.CanonicalizePath("dir"),
				Target:   node,
				Evidence: evidence.NewExplicitEvidence([]byte("map proof")),
			},
			{
				Path:     arcset.CanonicalizePath("@payload"),
				Target:   payload,
				Evidence: evidence.NewImplicitEvidence([]byte("block bytes")),
			},
		},
	}

	pl, err := ProofListFromTranscript(root, transcript)
	if err != nil {
		t.Fatalf("ProofListFromTranscript failed: %v", err)
	}
	if err := pl.ValidateShape(prooflist.RequireSteps()); err != nil {
		t.Fatalf("ValidateShape failed: %v", err)
	}
	if !pl.Root.Equals(root) {
		t.Fatalf("root = %v, want %v", pl.Root, root)
	}
	if len(pl.Steps) != 2 {
		t.Fatalf("steps len = %d, want 2", len(pl.Steps))
	}
	if pl.Steps[0].Kind != prooflist.KindMapStep {
		t.Fatalf("step 0 kind = %q, want %q", pl.Steps[0].Kind, prooflist.KindMapStep)
	}
	if pl.Steps[0].Path != "dir" || !pl.Steps[0].Target.Equals(node) {
		t.Fatalf("step 0 path/target not preserved: %#v", pl.Steps[0])
	}
	if !pl.Steps[0].From.Equals(root) {
		t.Fatalf("step 0 from = %v, want root %v", pl.Steps[0].From, root)
	}
	if pl.Steps[0].EvidenceKind != "explicit" {
		t.Fatalf("step 0 evidence kind = %q, want explicit", pl.Steps[0].EvidenceKind)
	}
	if !bytes.Equal(pl.Steps[0].Evidence, []byte("map proof")) {
		t.Fatalf("step 0 evidence bytes not preserved")
	}

	if pl.Steps[1].Kind != prooflist.KindPayloadBinding {
		t.Fatalf("step 1 kind = %q, want %q", pl.Steps[1].Kind, prooflist.KindPayloadBinding)
	}
	if !pl.Steps[1].From.Equals(node) {
		t.Fatalf("step 1 from = %v, want previous target %v", pl.Steps[1].From, node)
	}
	if pl.Steps[1].Path != "@payload" || !pl.Steps[1].Target.Equals(payload) {
		t.Fatalf("step 1 path/target not preserved: %#v", pl.Steps[1])
	}
	if pl.Steps[1].EvidenceKind != "implicit" {
		t.Fatalf("step 1 evidence kind = %q, want implicit", pl.Steps[1].EvidenceKind)
	}
}

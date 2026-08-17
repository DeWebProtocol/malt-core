package radix

import (
	"bytes"
	"context"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	materializermemory "github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment/kzg"
	"github.com/dewebprotocol/malt-core/auth/observation"
	"github.com/dewebprotocol/malt-core/auth/semantic/mapping"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

type phaseCollector struct{ samples []observation.Sample }

func (c *phaseCollector) ObservePhase(sample observation.Sample) {
	c.samples = append(c.samples, sample)
}

func TestProveReportsMaterializationOpenAndSerialization(t *testing.T) {
	scheme, err := kzg.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	semanticMap, err := NewMap(scheme, materializermemory.New(true))
	if err != nil {
		t.Fatal(err)
	}
	target := observedRawCID(t, []byte("target"))
	root, err := semanticMap.Commit(t.Context(), "observation", mapping.NewViewFrom(map[string]cid.Cid{"payload": target}))
	if err != nil {
		t.Fatal(err)
	}
	baselineBinding, baselineProof, err := semanticMap.Prove(context.Background(), "observation", root, arcset.Path("payload"))
	if err != nil {
		t.Fatal(err)
	}
	collector := new(phaseCollector)
	ctx := observation.WithObserver(context.Background(), collector)
	binding, proof, err := semanticMap.Prove(ctx, "observation", root, arcset.Path("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if !binding.Value.Equals(target) || len(proof) == 0 {
		t.Fatalf("binding=%#v proof=%d", binding, len(proof))
	}
	if binding.Present != baselineBinding.Present || !binding.Value.Equals(baselineBinding.Value) || !bytes.Equal(proof, baselineProof) {
		t.Fatalf("observation changed result: baseline=%#v/%x observed=%#v/%x", baselineBinding, baselineProof, binding, proof)
	}
	seen := map[observation.Phase]bool{}
	for _, sample := range collector.samples {
		seen[sample.Phase] = true
		if sample.Operations == 0 {
			t.Fatalf("empty observation sample = %#v", sample)
		}
	}
	for _, phase := range []observation.Phase{observation.PhaseMaterialization, observation.PhaseOpen, observation.PhaseSerialization} {
		if !seen[phase] {
			t.Fatalf("missing phase %q in %#v", phase, collector.samples)
		}
	}
}

func TestProveUsesOneRootBoundOpeningPerVisitedNode(t *testing.T) {
	base, err := kzg.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	scheme := &commitCountingRootScheme{IndexCommitment: base, rootProver: base}
	semanticMap, err := NewMap(scheme, materializermemory.New(true))
	if err != nil {
		t.Fatal(err)
	}
	target := observedRawCID(t, []byte("single-root-bound-opening"))
	root, err := semanticMap.Commit(t.Context(), "prove-once", mapping.NewViewFrom(map[string]cid.Cid{"payload": target}))
	if err != nil {
		t.Fatal(err)
	}
	scheme.proves = 0
	binding, proof, err := semanticMap.Prove(t.Context(), "prove-once", root, arcset.Path("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if !binding.Present || !binding.Value.Equals(target) || len(proof) == 0 {
		t.Fatalf("binding=%#v proof=%d", binding, len(proof))
	}
	if scheme.proves != 1 {
		t.Fatalf("ProveAtRoot calls = %d, want one opening for one visited radix node", scheme.proves)
	}
}

func observedRawCID(t *testing.T, data []byte) cid.Cid {
	t.Helper()
	digest, err := mh.Sum(data, mh.SHA2_256, -1)
	if err != nil {
		t.Fatal(err)
	}
	return cid.NewCidV1(cid.Raw, digest)
}

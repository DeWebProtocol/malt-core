package authentication_test

import (
	"context"
	"errors"
	"testing"

	"github.com/dewebprotocol/malt-core/derivation"
	"github.com/dewebprotocol/malt-core/engine"
	"github.com/dewebprotocol/malt-core/maltcid"
	"github.com/dewebprotocol/malt-core/sdk/authentication"
	cid "github.com/ipfs/go-cid"
)

func TestRetainedReadsPreserveIndependentBranches(t *testing.T) {
	e := pathEngine(t)
	a := cid.MustParse("bafkqaaa")
	b := cid.MustParse("bafkreigh2akiscaildcw4535x7k5vfhq56bqddhziq3p4mwfmlz4vfu2ta")
	w, err := authentication.BuildWriter(t.Context(), e, engine.State{
		Descriptor: maltcid.RootDescriptor{Layout: maltcid.Prefix, DerivationProfile: uint8(derivation.SHA256), Profile: maltcid.IPA256},
		Entries:    []engine.Entry{{Label: []byte("file"), Target: a}, {Label: []byte("unchanged"), Target: a}},
	})
	if err != nil {
		t.Fatal(err)
	}
	next, err := w.Apply(t.Context(), authentication.Delta{Changes: []engine.Change{{Label: []byte("file"), Before: a, After: b}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range []struct {
		w      *authentication.Writer
		target cid.Cid
	}{{w, a}, {next, b}} {
		if pair.w.Len() != 2 || pair.w.StateCharge() == 0 {
			t.Fatal("missing state accounting")
		}
		for _, label := range []string{"file", "unchanged", "missing"} {
			expected := pair.target
			if label == "unchanged" {
				expected = a
			}
			if label == "missing" {
				expected = cid.Undef
			}
			got, err := pair.w.Lookup(t.Context(), []byte(label))
			if err != nil || !got.Equals(expected) {
				t.Fatalf("lookup %s: %s %v", label, got, err)
			}
			nodes, err := pair.w.Nodes()
			if err != nil {
				t.Fatal(err)
			}
			proof, err := e.Prove(t.Context(), pair.w.Root(), []byte(label), nodes)
			if err != nil {
				t.Fatal(err)
			}
			if valid, err := e.Verify(pair.w.Root(), []byte(label), proof); err != nil || !valid || !proof.Target.Equals(expected) {
				t.Fatalf("proof %s: %v", label, err)
			}
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := w.Lookup(ctx, []byte("file")); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, invalid := range []*authentication.Writer{nil, {}} {
		if _, err := invalid.Nodes(); err == nil {
			t.Fatal("uninitialized nodes")
		}
		if _, err := invalid.Lookup(t.Context(), nil); err == nil {
			t.Fatal("uninitialized lookup")
		}
		if invalid.Len() != 0 || invalid.StateCharge() != 0 {
			t.Fatal("uninitialized accounting")
		}
	}
}

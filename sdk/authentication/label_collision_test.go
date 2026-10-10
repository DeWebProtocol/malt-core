package authentication

import (
	"errors"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
	"github.com/dewebprotocol/malt-core/derivation"
	"github.com/dewebprotocol/malt-core/engine"
	"github.com/dewebprotocol/malt-core/maltcid"
	cid "github.com/ipfs/go-cid"
)

func TestRetainedWriterRejectsCollidingLabelEvenForNoOp(t *testing.T) {
	scheme, err := ipa.NewCommitterScheme(ipa.ProfileDirect)
	if err != nil {
		t.Fatal(err)
	}
	profiles := engine.NewRegistry()
	if err := profiles.Register(scheme); err != nil {
		t.Fatal(err)
	}
	e := engine.New(profiles)
	value := cid.MustParse("bafkqaaa")
	d := maltcid.RootDescriptor{Layout: maltcid.Prefix, DerivationProfile: uint8(derivation.SHA256), Profile: maltcid.IPA256}
	original := engine.Entry{Label: []byte("original"), Target: value}
	w, err := BuildWriter(t.Context(), e, engine.State{Descriptor: d, Entries: []engine.Entry{original}})
	if err != nil {
		t.Fatal(err)
	}
	other := engine.Entry{Label: []byte("colliding"), Target: value}
	view, err := e.Interpret(engine.State{Descriptor: d, Entries: []engine.Entry{other}})
	if err != nil {
		t.Fatal(err)
	}
	// Seed the retained index with the state a derivation collision would produce:
	// lookup at the query coordinate finds a distinct, already retained label.
	// No production hash is replaced, and the no-op must fail before tree work.
	w.bindings = bindingSet(nil, view.Bindings[0].Coordinate, original)
	beforeBindings, beforeRoot := w.bindings, w.Root()
	if next, err := w.Update(t.Context(), engine.State{Descriptor: d, Entries: []engine.Entry{other}}); next != nil || !errors.Is(err, engine.ErrCoordinateCollision) {
		t.Fatalf("complete no-op update accepted colliding identity: next=%v err=%v", next, err)
	}
	for _, change := range []engine.Change{
		{Label: other.Label, Before: value, After: value},
		{Label: other.Label, Before: value},
		{Label: other.Label, After: value},
	} {
		if next, err := w.Apply(t.Context(), Delta{Changes: []engine.Change{change}}); next != nil || !errors.Is(err, engine.ErrCoordinateCollision) {
			t.Fatalf("delta accepted colliding identity: next=%v err=%v", next, err)
		}
	}
	if w.bindings != beforeBindings || !w.Root().Equals(beforeRoot) {
		t.Fatal("failed collision write mutated the base writer")
	}
}

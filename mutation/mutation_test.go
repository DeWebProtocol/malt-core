package mutation_test

import (
	"errors"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	"github.com/dewebprotocol/malt-core/mutation"
	cid "github.com/ipfs/go-cid"
)

func TestValidateRequiresBaseRootAndDeltas(t *testing.T) {
	if err := mutation.Validate(mutation.SemanticMutation{}); !errors.Is(err, mutation.ErrInvalidBaseRoot) {
		t.Fatalf("Validate error = %v, want ErrInvalidBaseRoot", err)
	}
	if err := mutation.Validate(mutation.SemanticMutation{BaseRoot: testCID(t)}); !errors.Is(err, mutation.ErrEmptyDeltas) {
		t.Fatalf("Validate error = %v, want ErrEmptyDeltas", err)
	}
}

func TestValidateAcceptsPortableMapDelta(t *testing.T) {
	target := arcset.NewCASTarget(testCID(t))
	coordinate, err := arcset.NewMapCoordinate("profile/name")
	if err != nil {
		t.Fatal(err)
	}
	delta, err := arcset.NewCanonicalArcDelta(arcset.KindMap, []arcset.ArcChange{{Coordinate: coordinate, After: &target}})
	if err != nil {
		t.Fatal(err)
	}
	err = mutation.Validate(mutation.SemanticMutation{
		BaseRoot: testCID(t),
		Deltas:   []mutation.ArcSetDelta{{Kind: arcset.KindMap, Changes: delta}},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func testCID(t *testing.T) cid.Cid {
	t.Helper()
	value, err := cid.Parse("bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku")
	if err != nil {
		t.Fatal(err)
	}
	return value
}

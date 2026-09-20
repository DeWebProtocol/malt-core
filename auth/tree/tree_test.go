package tree_test

import (
	"context"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
	"github.com/dewebprotocol/malt-core/auth/coordinate"
	"github.com/dewebprotocol/malt-core/auth/tree"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

func newTree(t *testing.T) *tree.Engine {
	t.Helper()
	s, err := ipa.NewCommitterScheme(ipa.ProfileDirect)
	if err != nil {
		t.Fatal(err)
	}
	r := tree.NewRegistry()
	if err := r.Register(s); err != nil {
		t.Fatal(err)
	}
	return tree.New(r)
}
func TestTreeConsumesCoordinatesWithoutInputRules(t *testing.T) {
	e := newTree(t)
	nodes := memory.NewNodes()
	target := cid.MustParse("bafkqaaa")
	// The tree does not install or execute application interpretation rule 240.
	d := maltcid.RootDescriptor{Layout: maltcid.Prefix, InputRule: 240, Profile: maltcid.IPA256}
	k := coordinate.Value{Kind: coordinate.Key, Key: [32]byte{1}}
	root, err := e.Commit(t.Context(), tree.View{Descriptor: d, Bindings: []tree.CoordinateBinding{{Coordinate: k, Target: target}}}, nodes)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := e.Prove(t.Context(), root, k, nodes)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := e.Verify(root, k, proof); err != nil || !ok {
		t.Fatal("coordinate proof", err)
	}
	if _, err := e.Prove(t.Context(), root, coordinate.At(0), nodes); err == nil {
		t.Fatal("wrong coordinate kind accepted")
	}
}

type rewritingSink struct{}

func (rewritingSink) PutNode(_ context.Context, ref maltcid.NodeRef, cells []commitment.Cell) error {
	for i := range ref.Commitment {
		ref.Commitment[i] = 0
	}
	for i := range cells {
		clear(cells[i])
	}
	return nil
}

type rewritingSource struct {
	nodes *memory.Nodes
	other maltcid.NodeRef
}

func (s rewritingSource) GetNode(ctx context.Context, ref maltcid.NodeRef) ([]commitment.Cell, error) {
	copy(ref.Commitment, s.other.Commitment)
	return s.nodes.GetNode(ctx, s.other)
}
func TestMaterializerCannotRewriteSelectedCommitment(t *testing.T) {
	e := newTree(t)
	nodes := memory.NewNodes()
	d := maltcid.RootDescriptor{Layout: maltcid.Positional, Profile: maltcid.IPA256}
	state := tree.View{Descriptor: d, Bindings: []tree.CoordinateBinding{{Coordinate: coordinate.At(0), Target: cid.MustParse("bafkqaaa")}}}
	root, err := e.Commit(t.Context(), state, nodes)
	if err != nil {
		t.Fatal(err)
	}
	other, err := e.Commit(t.Context(), state, rewritingSink{})
	if err != nil {
		t.Fatal(err)
	}
	if !root.Equals(other) {
		t.Fatal("output materializer rewrote the computed Root")
	}
	state.Bindings[0].Target = cid.MustParse("bafkreigh2akiscaildcw4535x7k5vfhq56bqddhziq3p4mwfmlz4vfu2ta")
	other, err = e.Commit(t.Context(), state, nodes)
	if err != nil {
		t.Fatal(err)
	}
	ref, _, _ := maltcid.RootNode(other)
	if _, _, err := e.Import(t.Context(), root, rewritingSource{nodes: nodes, other: ref}, 1); err == nil {
		t.Fatal("input materializer changed the Root being verified")
	}
}

type forgedWorkspace struct {
	*tree.Workspace
	target cid.Cid
}

func (s forgedWorkspace) GetNode(ctx context.Context, ref maltcid.NodeRef) ([]commitment.Cell, error) {
	cells, err := s.Workspace.GetNode(ctx, ref)
	if err != nil {
		return nil, err
	}
	cells[1] = append(commitment.Cell{maltcid.PositionalLeafCell}, s.target.Bytes()...)
	return cells, nil
}
func TestWrappingOwnedMaterializationDoesNotGrantVerificationBypass(t *testing.T) {
	e := newTree(t)
	nodes := memory.NewNodes()
	original := cid.MustParse("bafkqaaa")
	forged := cid.MustParse("bafkreigh2akiscaildcw4535x7k5vfhq56bqddhziq3p4mwfmlz4vfu2ta")
	root, err := e.Commit(t.Context(), tree.View{Descriptor: maltcid.RootDescriptor{Layout: maltcid.Positional, Profile: maltcid.IPA256}, Bindings: []tree.CoordinateBinding{{Coordinate: coordinate.At(0), Target: original}}}, nodes)
	if err != nil {
		t.Fatal(err)
	}
	owned, _, err := e.Import(t.Context(), root, nodes, 1)
	if err != nil {
		t.Fatal(err)
	}
	work, err := e.Workspace(owned)
	if err != nil {
		t.Fatal(err)
	}
	source := forgedWorkspace{Workspace: work, target: forged}
	if _, err := e.Apply(t.Context(), root, []tree.Change{{Coordinate: coordinate.At(0), Before: forged, After: original}}, source, work); err == nil {
		t.Fatal("foreign wrapper inherited trusted-source status")
	}
}

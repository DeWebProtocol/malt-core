package engine_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
	"github.com/dewebprotocol/malt-core/auth/commitment/kzg"
	"github.com/dewebprotocol/malt-core/auth/coordinate"
	"github.com/dewebprotocol/malt-core/derivation"
	"github.com/dewebprotocol/malt-core/engine"
	"github.com/dewebprotocol/malt-core/traversal"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

func target(text string) cid.Cid {
	sum, _ := mh.Sum([]byte(text), mh.SHA2_256, -1)
	return cid.NewCidV1(cid.Raw, sum)
}
func setup(t *testing.T, id maltcid.ProfileID) (*engine.Engine, *memory.Nodes) {
	t.Helper()
	r := engine.NewRegistry()
	var s engine.Profile
	var err error
	if id == maltcid.IPA256 {
		s, err = ipa.NewCommitterScheme(ipa.ProfileDirect)
	} else {
		s, err = kzg.NewScheme()
	}
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Register(s); err != nil {
		t.Fatal(err)
	}
	return engine.New(r), memory.NewNodes()
}

func TestLabelNativeEquivalenceAndProofs(t *testing.T) {
	for _, id := range []maltcid.ProfileID{maltcid.IPA256, maltcid.KZG4096} {
		t.Run(string(rune(id+'0')), func(t *testing.T) {
			e, nodes := setup(t, id)
			ctx := context.Background()
			d := maltcid.RootDescriptor{Layout: maltcid.Prefix, DerivationProfile: uint8(derivation.SHA256), Profile: id}
			state := engine.State{Descriptor: d, Entries: []engine.Entry{{Label: []byte("a/b"), Target: target("one")}, {Label: []byte("@payload"), Target: target("payload")}}}
			root, err := e.Build(ctx, state, nodes)
			if err != nil {
				t.Fatal(err)
			}
			nodeCount := nodes.Len()
			native := engine.State{Descriptor: d}
			native.Descriptor.DerivationProfile = uint8(derivation.Direct)
			for _, entry := range state.Entries {
				k, err := derivation.Derive(derivation.SHA256, entry.Label)
				if err != nil {
					t.Fatal(err)
				}
				native.Entries = append(native.Entries, engine.Entry{Label: coordinate.EncodeKey(k.Key), Target: entry.Target})
			}
			other, err := e.Build(ctx, native, nodes)
			if err != nil {
				t.Fatal(err)
			}
			a, _ := maltcid.ExtractCommitment(root)
			b, _ := maltcid.ExtractCommitment(other)
			if root.Equals(other) || !bytes.Equal(a, b) || nodes.Len() != nodeCount {
				t.Fatal("normalized state failed to reuse commitment/materialization")
			}
			for _, entry := range state.Entries {
				result, err := e.Prove(ctx, root, entry.Label, nodes)
				if err != nil {
					t.Fatal(err)
				}
				ok, err := e.Verify(root, entry.Label, result)
				if err != nil || !ok || !result.Target.Equals(entry.Target) {
					t.Fatalf("membership %v %v", ok, err)
				}
				result.Target = target("tampered")
				ok, _ = e.Verify(root, entry.Label, result)
				if ok {
					t.Fatal("tampered result verified")
				}
			}
			missing := []byte("missing")
			result, err := e.Prove(ctx, root, missing, nodes)
			if err != nil {
				t.Fatal(err)
			}
			valid, err := e.Verify(root, missing, result)
			if err != nil || !valid || result.Present {
				t.Fatalf("absence %v", err)
			}
			if _, err := e.Prove(ctx, root, missing, memory.NewNodes()); err == nil {
				t.Fatal("missing materialization reported as absence")
			}
			state.Entries = append(state.Entries, state.Entries[0])
			if _, err := e.Build(ctx, state, nodes); err == nil {
				t.Fatal("duplicate authenticated key accepted")
			}
			state = engine.State{Descriptor: d}
			state.Descriptor.DerivationProfile = 240
			if _, err := e.Build(ctx, state, nodes); err == nil {
				t.Fatal("empty state accepted unknown AA")
			}
		})
	}
}

func TestNativePrefixDepthAndMixedRootTraversal(t *testing.T) {
	e, nodes := setup(t, maltcid.IPA256)
	ctx := context.Background()
	d := maltcid.RootDescriptor{DerivationProfile: uint8(derivation.Direct), Layout: maltcid.Prefix, Profile: maltcid.IPA256}
	a := [32]byte{}
	b := a
	b[31] = 1
	state := engine.State{Descriptor: d, Entries: []engine.Entry{{Label: coordinate.EncodeKey(a), Target: target("a")}, {Label: coordinate.EncodeKey(b), Target: target("b")}}}
	root, err := e.Build(ctx, state, nodes)
	if err != nil {
		t.Fatal(err)
	}
	result, err := e.Prove(ctx, root, coordinate.EncodeKey(b), nodes)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Proof.Nodes) != 32 {
		t.Fatal("native key was hashed or truncated")
	}
	if valid, err := e.Verify(root, coordinate.EncodeKey(b), result); err != nil || !valid {
		t.Fatal("deep prefix proof", err)
	}
	parent := engine.State{Descriptor: d, Entries: []engine.Entry{{Label: []byte("a/b"), Target: root}}}
	parent.Descriptor.DerivationProfile = uint8(derivation.SHA256)
	entryRoot, err := e.Build(ctx, parent, nodes)
	if err != nil {
		t.Fatal(err)
	}
	steps := [][]byte{[]byte("a/b"), coordinate.EncodeKey(b)}
	got, proof, err := traversal.Resolve(ctx, e, entryRoot, steps, nodes)
	if err != nil {
		t.Fatal(err)
	}
	valid, err := traversal.Verify(e, entryRoot, steps, got, proof)
	if err != nil || !valid || !got.Equals(target("b")) {
		t.Fatal("cross-AA traversal", err)
	}
}

func TestPositionalMetadataAndOpaqueDirectLabels(t *testing.T) {
	e, nodes := setup(t, maltcid.IPA256)
	ctx := context.Background()
	state := engine.State{Descriptor: maltcid.RootDescriptor{DerivationProfile: uint8(derivation.Direct), Layout: maltcid.Positional, Profile: maltcid.IPA256}, ChunkSize: 10, TotalSize: 2553}
	for i := 0; i < 256; i++ {
		state.Entries = append(state.Entries, engine.Entry{Label: coordinate.EncodeIndex(uint64(i)), Target: target("chunk")})
	}
	root, err := e.Build(ctx, state, nodes)
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range []uint64{0, 254, 255, 256, ^uint64(0)} {
		q := coordinate.EncodeIndex(i)
		result, err := e.Prove(ctx, root, q, nodes)
		if err != nil {
			t.Fatal(i, err)
		}
		valid, err := e.Verify(root, q, result)
		if err != nil || !valid || result.Present != (i < 256) {
			t.Fatalf("index %d: %v %v", i, valid, err)
		}
	}
	if result, err := e.Prove(ctx, root, []byte("@payload"), nodes); err != nil || result.Present {
		t.Fatal("eight-byte label should be an ordinary absent index", err)
	}
	state.Entries[0].Label = []byte("@payload")
	if _, err := e.Build(ctx, state, nodes); err == nil {
		t.Fatal("Positional system binding committed")
	}
}

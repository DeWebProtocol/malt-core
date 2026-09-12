package engine_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
	"github.com/dewebprotocol/malt-core/auth/commitment/kzg"
	"github.com/dewebprotocol/malt-core/auth/engine"
	"github.com/dewebprotocol/malt-core/auth/input"
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
	var s engine.ProfileVerifier
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
	return engine.New(input.DefaultRegistry(), r), memory.NewNodes()
}

func TestLabelNativeEquivalenceAndProofs(t *testing.T) {
	for _, id := range []maltcid.ProfileID{maltcid.IPA256, maltcid.KZG4096} {
		t.Run(string(rune(id+'0')), func(t *testing.T) {
			e, nodes := setup(t, id)
			ctx := context.Background()
			d := maltcid.RootDescriptor{Layout: maltcid.Prefix, InputRule: uint8(input.BytesSHA256), Profile: id}
			state := engine.State{Descriptor: d, Entries: []engine.Entry{{Input: input.LabelValue([]byte("a/b")), Target: target("one")}, {Input: input.SystemValue(input.Payload), Target: target("payload")}}}
			root, err := e.Build(ctx, state, nodes)
			if err != nil {
				t.Fatal(err)
			}
			nodeCount := nodes.Len()
			native := engine.State{Descriptor: d}
			native.Descriptor.InputRule = uint8(input.Direct)
			for _, entry := range state.Entries {
				k, err := e.Rules.Derive(input.BytesSHA256, entry.Input)
				if err != nil {
					t.Fatal(err)
				}
				native.Entries = append(native.Entries, engine.Entry{Input: input.KeyValue(k.Key), Target: entry.Target})
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
				result, err := e.Prove(ctx, root, entry.Input, nodes)
				if err != nil {
					t.Fatal(err)
				}
				ok, err := e.Verify(root, entry.Input, result)
				if err != nil || !ok || !result.Target.Equals(entry.Target) {
					t.Fatalf("membership %v %v", ok, err)
				}
				result.Target = target("tampered")
				ok, _ = e.Verify(root, entry.Input, result)
				if ok {
					t.Fatal("tampered result verified")
				}
			}
			missing := input.LabelValue([]byte("missing"))
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
			state.Descriptor.InputRule = 240
			if _, err := e.Build(ctx, state, nodes); err == nil {
				t.Fatal("empty state accepted unknown AA")
			}
		})
	}
}

func TestNativePrefixDepthAndMixedRootTraversal(t *testing.T) {
	e, nodes := setup(t, maltcid.IPA256)
	ctx := context.Background()
	d := maltcid.RootDescriptor{Layout: maltcid.Prefix, Profile: maltcid.IPA256}
	a := [32]byte{}
	b := a
	b[31] = 1
	state := engine.State{Descriptor: d, Entries: []engine.Entry{{Input: input.KeyValue(a), Target: target("a")}, {Input: input.KeyValue(b), Target: target("b")}}}
	root, err := e.Build(ctx, state, nodes)
	if err != nil {
		t.Fatal(err)
	}
	result, err := e.Prove(ctx, root, input.KeyValue(b), nodes)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Proof.Nodes) != 32 {
		t.Fatal("native key was hashed or truncated")
	}
	if valid, err := e.Verify(root, input.KeyValue(b), result); err != nil || !valid {
		t.Fatal("deep prefix proof", err)
	}
	parent := engine.State{Descriptor: d, Entries: []engine.Entry{{Input: input.LabelValue([]byte("a/b")), Target: root}}}
	parent.Descriptor.InputRule = uint8(input.BytesSHA256)
	entryRoot, err := e.Build(ctx, parent, nodes)
	if err != nil {
		t.Fatal(err)
	}
	steps := []input.Value{input.LabelValue([]byte("a/b")), input.KeyValue(b)}
	got, proof, err := e.Resolve(ctx, entryRoot, steps, nodes)
	if err != nil {
		t.Fatal(err)
	}
	valid, err := e.VerifyTraversal(entryRoot, steps, got, proof)
	if err != nil || !valid || !got.Equals(target("b")) {
		t.Fatal("cross-AA traversal", err)
	}
}

func TestPositionalMetadataAndNoSystemBindings(t *testing.T) {
	e, nodes := setup(t, maltcid.IPA256)
	ctx := context.Background()
	state := engine.State{Descriptor: maltcid.RootDescriptor{Layout: maltcid.Positional, Profile: maltcid.IPA256}, ChunkSize: 10, TotalSize: 2553}
	for i := 0; i < 256; i++ {
		state.Entries = append(state.Entries, engine.Entry{Input: input.IndexValue(uint64(i)), Target: target("chunk")})
	}
	root, err := e.Build(ctx, state, nodes)
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range []uint64{0, 254, 255, 256, ^uint64(0)} {
		q := input.IndexValue(i)
		result, err := e.Prove(ctx, root, q, nodes)
		if err != nil {
			t.Fatal(i, err)
		}
		valid, err := e.Verify(root, q, result)
		if err != nil || !valid || result.Present != (i < 256) {
			t.Fatalf("index %d: %v %v", i, valid, err)
		}
	}
	if _, err := e.Prove(ctx, root, input.SystemValue(input.Payload), nodes); err == nil {
		t.Fatal("Positional accepted system binding")
	}
	state.Entries[0].Input = input.SystemValue(input.Payload)
	if _, err := e.Build(ctx, state, nodes); err == nil {
		t.Fatal("Positional system binding committed")
	}
}

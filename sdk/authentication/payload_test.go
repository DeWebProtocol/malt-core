package authentication_test

import (
	"testing"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/engine"
	"github.com/dewebprotocol/malt-core/auth/input"
	"github.com/dewebprotocol/malt-core/protocol"
	"github.com/dewebprotocol/malt-core/sdk/authentication"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

func TestFlatAndRootedPayloadQueryComposition(t *testing.T) {
	e := pathEngine(t)
	nodes := memory.NewNodes()
	manifest := cid.MustParse("bafkqaaa")
	literal := cid.MustParse("bafkreigh2akiscaildcw4535x7k5vfhq56bqddhziq3p4mwfmlz4vfu2ta")
	descriptor := maltcid.RootDescriptor{Layout: maltcid.Prefix, InputRule: 1, Profile: maltcid.IPA256}
	build := func(entries ...engine.Entry) cid.Cid {
		t.Helper()
		root, err := e.Build(t.Context(), engine.State{Descriptor: descriptor, Entries: entries}, nodes)
		if err != nil {
			t.Fatal(err)
		}
		return root
	}
	payload := input.SystemValue(input.Payload)
	child := build(engine.Entry{Input: payload, Target: manifest}, engine.Entry{Input: input.LabelValue([]byte("@payload")), Target: literal})
	rooted := build(engine.Entry{Input: input.LabelValue([]byte("file")), Target: child})
	flat := build(engine.Entry{Input: input.LabelValue([]byte("file")), Target: manifest}, engine.Entry{Input: payload, Target: manifest})
	for _, tc := range []struct {
		name   string
		root   cid.Cid
		steps  []input.Value
		target cid.Cid
	}{
		{"rooted content", rooted, []input.Value{input.LabelValue([]byte("file")), payload}, manifest},
		{"rooted relation", rooted, []input.Value{input.LabelValue([]byte("file"))}, child},
		{"flat content", flat, []input.Value{input.LabelValue([]byte("file"))}, manifest},
		{"flat entry manifest", flat, []input.Value{payload}, manifest},
		{"literal label", child, []input.Value{input.LabelValue([]byte("@payload"))}, literal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := protocol.AuthenticationRequest{Profile: protocol.AuthenticationPathProfile, Root: tc.root.String(), Operation: "resolve", Steps: tc.steps}
			r, err := authentication.Execute(t.Context(), e, q, nodes)
			if err != nil {
				t.Fatal(err)
			}
			if r.Resolved != tc.target.String() || len(r.Traversal.Results) != len(tc.steps) {
				t.Fatal("query step was added or skipped")
			}
			if valid, err := authentication.Verify(e, q, r); err != nil || !valid {
				t.Fatal("query did not verify", err)
			}
			r.Traversal.Results = r.Traversal.Results[:len(r.Traversal.Results)-1]
			if valid, _ := authentication.Verify(e, q, r); valid {
				t.Fatal("missing terminal binding accepted")
			}
		})
	}
	// Positional roots do not acquire payload bindings during composition.
	positional, err := e.Build(t.Context(), engine.State{Descriptor: maltcid.RootDescriptor{Layout: maltcid.Positional, Profile: maltcid.IPA256}}, nodes)
	if err != nil {
		t.Fatal(err)
	}
	q := protocol.AuthenticationRequest{Profile: protocol.AuthenticationPathProfile, Root: positional.String(), Operation: "resolve", Steps: []input.Value{payload}}
	if _, err := authentication.Execute(t.Context(), e, q, nodes); err == nil {
		t.Fatal("Positional accepted system payload")
	}
}

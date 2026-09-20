package authentication_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
	"github.com/dewebprotocol/malt-core/auth/engine"
	"github.com/dewebprotocol/malt-core/auth/input"
	"github.com/dewebprotocol/malt-core/protocol"
	"github.com/dewebprotocol/malt-core/sdk/authentication"
	authverifier "github.com/dewebprotocol/malt-core/sdk/authentication/verifier"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

func TestCandidateRoundTripCustomAAAndIndependentVerification(t *testing.T) {
	ctx := context.Background()
	scheme, err := ipa.NewCommitterScheme(ipa.ProfileDirect)
	if err != nil {
		t.Fatal(err)
	}
	profiles := engine.NewRegistry()
	if err := profiles.Register(scheme); err != nil {
		t.Fatal(err)
	}
	rules := input.DefaultRegistry()
	// This rule deliberately gives slash no meaning and delegates only hashing.
	if err := rules.Register(128, input.RuleFunc(func(v input.Value) (input.Coordinate, error) {
		return input.DefaultRegistry().Derive(input.BytesSHA256, v)
	})); err != nil {
		t.Fatal(err)
	}
	e := engine.New(rules, profiles)
	sum, _ := mh.Sum([]byte("payload"), mh.SHA2_256, -1)
	target := cid.NewCidV1(cid.Raw, sum)
	selector := input.LabelValue([]byte{'a', '/', 0xff})
	state := engine.State{Descriptor: maltcid.RootDescriptor{Layout: maltcid.Prefix, InputRule: 128, Profile: maltcid.IPA256}, Entries: []engine.Entry{{Input: selector, Target: target}}}
	candidate, err := authentication.Prepare(ctx, e, state)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(candidate)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err = protocol.DecodeAuthenticationCandidate(raw)
	if err != nil {
		t.Fatal(err)
	}
	nodes := memory.NewNodes()
	if err := authentication.Materialize(ctx, e, candidate, nodes); err != nil {
		t.Fatal(err)
	}
	q := protocol.AuthenticationRequest{Profile: protocol.AuthenticationPathProfile, Root: candidate.Root, Steps: []input.Value{}, Operation: "binding", Input: &selector}
	result, err := authentication.Execute(ctx, e, q, nodes)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(protocol.AuthenticationVerification{Request: q, Result: result})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := protocol.DecodeAuthenticationVerification(wire)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := authverifier.New(rules, maltcid.IPA256)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := authentication.Verify(verifier, decoded.Request, decoded.Result); err != nil || !ok {
		t.Fatalf("verify %v %v", ok, err)
	}
	other, err := authverifier.New(nil, maltcid.IPA256)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := authentication.Verify(other, q, result); ok {
		t.Fatal("unknown AA verified")
	}
	result.Binding.Target = cid.Undef
	if ok, _ := authentication.Verify(verifier, q, result); ok {
		t.Fatal("tampered target verified")
	}
	candidate.Nodes[0].Cells[0] = []byte("tampered")
	empty := memory.NewNodes()
	if err := authentication.Materialize(ctx, e, candidate, empty); err == nil || empty.Len() != 0 {
		t.Fatal("invalid candidate written")
	}
}

func TestTypedWireRejectsAmbiguousInputs(t *testing.T) {
	for _, raw := range []string{`{"kind":"index","number":1}`, `{"kind":"index","number":"01"}`, `{"kind":"label","data":"YQ==","number":"0"}`, `{"kind":"key","data":"YQ=="}`, `{"kind":"label","data":null}`} {
		var v input.Value
		if err := json.Unmarshal([]byte(raw), &v); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	index := input.IndexValue(^uint64(0))
	data, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"18446744073709551615"`) {
		t.Fatalf("uint64 lost precision %s", data)
	}
	var round input.Value
	if err := json.Unmarshal(data, &round); err != nil || round.Number != index.Number {
		t.Fatal(err)
	}
	if _, err := protocol.DecodeAuthenticationRequest([]byte(`{"profile":"malt.authentication/1","profile":"malt.authentication/1"}`)); err == nil {
		t.Fatal("duplicate field accepted")
	}
}

package authentication_test

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
	"github.com/dewebprotocol/malt-core/auth/coordinate"
	"github.com/dewebprotocol/malt-core/derivation"
	"github.com/dewebprotocol/malt-core/engine"
	"github.com/dewebprotocol/malt-core/protocol"
	"github.com/dewebprotocol/malt-core/sdk/authentication"
	authbuiltin "github.com/dewebprotocol/malt-core/sdk/authentication/builtin"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

func TestCandidateRoundTripOpaqueLabelsAndIndependentVerification(t *testing.T) {
	ctx := context.Background()
	scheme, err := ipa.NewCommitterScheme(ipa.ProfileDirect)
	if err != nil {
		t.Fatal(err)
	}
	profiles := engine.NewRegistry()
	if err := profiles.Register(scheme); err != nil {
		t.Fatal(err)
	}
	e := engine.New(profiles)
	sum, _ := mh.Sum([]byte("payload"), mh.SHA2_256, -1)
	target := cid.NewCidV1(cid.Raw, sum)
	selector := []byte{'a', '/', 0xff}
	state := engine.State{Descriptor: maltcid.RootDescriptor{Layout: maltcid.Prefix, DerivationProfile: uint8(derivation.SHA256), Profile: maltcid.IPA256}, Entries: []engine.Entry{{Label: selector, Target: target}}}
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
	q := protocol.AuthenticationRequest{Profile: protocol.AuthenticationPathProfile, Root: candidate.Root, Steps: [][]byte{}, Operation: "binding", Label: &selector}
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
	verifier, err := authbuiltin.NewVerifier(maltcid.IPA256)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := authentication.Verify(verifier, decoded.Request, decoded.Result); err != nil || !ok {
		t.Fatalf("verify %v %v", ok, err)
	}
	d, commitment, _ := maltcid.ParseRoot(cid.MustParse(q.Root))
	d.DerivationProfile = 128
	unknown, _ := maltcid.NewRoot(d, commitment)
	unknownQuery := q
	unknownQuery.Root = unknown.String()
	if ok, _ := authentication.Verify(verifier, unknownQuery, result); ok {
		t.Fatal("unknown derivation verified")
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
		var v []byte
		if err := json.Unmarshal([]byte(raw), &v); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	index := coordinate.EncodeIndex(^uint64(0))
	data, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `"//////////8="` {
		t.Fatalf("uint64 lost precision %s", data)
	}
	var round []byte
	if err := json.Unmarshal(data, &round); err != nil || !bytes.Equal(round, index) {
		t.Fatal(err)
	}
	if _, err := protocol.DecodeAuthenticationRequest([]byte(`{"profile":"malt.authentication/3","profile":"malt.authentication/3"}`)); err == nil {
		t.Fatal("duplicate field accepted")
	}
}

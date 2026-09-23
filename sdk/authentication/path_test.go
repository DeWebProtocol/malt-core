package authentication_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
	"github.com/dewebprotocol/malt-core/derivation"
	"github.com/dewebprotocol/malt-core/engine"
	"github.com/dewebprotocol/malt-core/protocol"
	"github.com/dewebprotocol/malt-core/sdk/authentication"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
)

func pathEngine(t *testing.T) *engine.Engine {
	t.Helper()
	scheme, err := ipa.NewCommitterScheme(ipa.ProfileDirect)
	if err != nil {
		t.Fatal(err)
	}
	profiles := engine.NewRegistry()
	if err := profiles.Register(scheme); err != nil {
		t.Fatal(err)
	}
	return engine.New(profiles)
}

func TestPathAbsenceBindsPrefixAndRejectsFailures(t *testing.T) {
	ctx := context.Background()
	e := pathEngine(t)
	nodes := memory.NewNodes()
	d := maltcid.RootDescriptor{Layout: maltcid.Prefix, DerivationProfile: uint8(derivation.SHA256), Profile: maltcid.IPA256}
	child, err := e.Build(ctx, engine.State{Descriptor: d}, nodes)
	if err != nil {
		t.Fatal(err)
	}
	root, err := e.Build(ctx, engine.State{Descriptor: d, Entries: []engine.Entry{{Label: []byte("child"), Target: child}}}, nodes)
	if err != nil {
		t.Fatal(err)
	}
	q := protocol.AuthenticationRequest{Profile: protocol.AuthenticationPathProfile, Root: root.String(), Operation: "resolve", Steps: [][]byte{[]byte("child"), []byte("missing"), []byte("suffix")}}
	result, err := authentication.Execute(ctx, e, q, nodes)
	if err != nil {
		t.Fatal(err)
	}
	if result.AbsentStep == nil || *result.AbsentStep != 1 || result.Resolved != "" {
		t.Fatalf("unexpected absence: %+v", result)
	}
	wire, err := json.Marshal(protocol.AuthenticationVerification{Request: q, Result: result})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := protocol.DecodeAuthenticationVerification(wire)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := authentication.Verify(e, decoded.Request, decoded.Result); !ok || err != nil {
		t.Fatalf("roundtrip: %v %v", ok, err)
	}
	altered := q
	altered.Steps = append([][]byte(nil), q.Steps...)
	altered.Steps[0] = []byte("other")
	if ok, _ := authentication.Verify(e, altered, result); ok {
		t.Fatal("wrong prefix verified")
	}
	shortened := result
	shortened.Traversal.Results = shortened.Traversal.Results[:1]
	if ok, _ := authentication.Verify(e, q, shortened); ok {
		t.Fatal("truncated proof verified")
	}
	wrong := result
	step := uint64(0)
	wrong.AbsentStep = &step
	if ok, _ := authentication.Verify(e, q, wrong); ok {
		t.Fatal("wrong absent step verified")
	}
	if _, err := authentication.Execute(ctx, e, q, memory.NewNodes()); err == nil {
		t.Fatal("missing materialization became absence")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := authentication.Execute(canceled, e, q, nodes); err == nil {
		t.Fatal("cancellation became absence")
	}
	q.Profile = protocol.AuthenticationProfile
	if _, err := authentication.Execute(ctx, e, q, nodes); err == nil {
		t.Fatal("obsolete query profile was accepted")
	}
	if ok, _ := authentication.Verify(e, q, result); ok {
		t.Fatal("cross-profile result verified")
	}
}

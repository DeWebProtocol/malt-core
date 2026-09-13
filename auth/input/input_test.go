package input_test

import (
	"github.com/dewebprotocol/malt-core/auth/input"
	"testing"
)

func TestRulesPreserveOpaqueLabelsAndNativeKeys(t *testing.T) {
	r := input.DefaultRegistry()
	a, err := r.Derive(input.BytesSHA256, input.LabelValue([]byte("/a//b/")))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := r.Derive(input.BytesSHA256, input.LabelValue([]byte("a/b")))
	if a == b {
		t.Fatal("labels were normalized")
	}
	native, err := r.Derive(input.Direct, input.KeyValue(a.Key))
	if err != nil || native != a {
		t.Fatalf("native key was transformed: %v", err)
	}
	system, _ := r.Derive(input.BytesSHA256, input.SystemValue(input.Payload))
	label, _ := r.Derive(input.BytesSHA256, input.LabelValue([]byte("@payload")))
	if system == label {
		t.Fatal("system/application namespace collision")
	}
	if _, err := r.Derive(input.UnixFSNameSHA256, input.LabelValue([]byte("a/b"))); err == nil {
		t.Fatal("UnixFS accepted path as a name")
	}
	if _, err := r.Derive(input.BytesSHA256, input.LabelValue([]byte{0xff, 0, 0x2f})); err != nil {
		t.Fatal("opaque labels gained UnixFS constraints", err)
	}
}
func TestRegistrationIsExplicitAndImmutable(t *testing.T) {
	r := input.DefaultRegistry()
	if err := r.Register(input.Direct, input.RuleFunc(nil)); err == nil {
		t.Fatal("nil function registered")
	}
	if err := r.Register(input.Direct, input.RuleFunc(func(input.Value) (input.Coordinate, error) { return input.Coordinate{}, nil })); err == nil {
		t.Fatal("registered ID overwritten")
	}
	if _, err := r.Derive(200, input.LabelValue([]byte("a"))); err == nil {
		t.Fatal("unknown AA fell back")
	}
	if _, err := r.Derive(input.Direct, input.Value{Kind: input.Key, Data: []byte{1}}); err == nil {
		t.Fatal("short key accepted")
	}
	if _, err := r.Derive(input.Direct, input.SystemValue(input.Payload)); err == nil {
		t.Fatal("direct mode invented a system key")
	}
}

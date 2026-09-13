package protocol_test

import (
	"encoding/json"
	"fmt"
	"github.com/dewebprotocol/malt-core/auth/input"
	"github.com/dewebprotocol/malt-core/protocol"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	"testing"
)

func TestAuthenticationJSONExactFieldNamesAndValues(t *testing.T) {
	root, err := maltcid.NewRoot(maltcid.RootDescriptor{Layout: maltcid.Positional, Profile: maltcid.IPA256}, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	prefix := fmt.Sprintf(`{"profile":"malt.authentication/0","root":%q,`, root.String())
	for _, body := range []string{
		`"operation":"resolve","start":null}`,
		`"operation":"binding","input":{"kind":"index","number":"0","data":null}}`,
		`"operation":"binding","input":{"kind":"label","data":"YQ==","number":null}}`,
		`"operation":"binding","input":{"Kind":"index","number":"0"}}`,
		`"Operation":"resolve"}`,
		`"operation":"range","start":"00"}`,
		`"operation":"range","start":"+1"}`,
		`"operation":"range","start":"0","end":null}`,
	} {
		if _, err := protocol.DecodeAuthenticationRequest([]byte(prefix + body)); err == nil {
			t.Fatal("accepted noncanonical envelope", body)
		}
	}
	for _, body := range []string{`"operation":"resolve"}`, `"operation":"range","start":"18446744073709551615"}`} {
		if _, err := protocol.DecodeAuthenticationRequest([]byte(prefix + body)); err != nil {
			t.Fatal(err)
		}
	}
	for _, raw := range []string{
		`{"kind":"index","number":"0","data":null}`,
		`{"kind":"label","data":"YQ==","number":null}`,
		`{"kind":"label","data":"YQ==","data":"Yg=="}`,
		`{"kind":"label","data":"YR=="}`,
		`{"kind":"label","data":"YQ==\n"}`,
	} {
		var v input.Value
		if json.Unmarshal([]byte(raw), &v) == nil {
			t.Fatal("accepted invalid typed input", raw)
		}
	}
	for _, raw := range []string{
		`{"descriptor":{"layout":2,"vc_profile":2},"entries":[],"chunk_size":"01"}`,
		`{"descriptor":{"Layout":2,"vc_profile":2},"entries":[]}`,
	} {
		if _, err := protocol.DecodeAuthenticationState([]byte(raw)); err == nil {
			t.Fatal("accepted malformed state", raw)
		}
	}
}

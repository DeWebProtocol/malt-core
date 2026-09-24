package protocol_test

import (
	"fmt"
	"testing"

	"github.com/dewebprotocol/malt-core/derivation"
	"github.com/dewebprotocol/malt-core/maltcid"
	"github.com/dewebprotocol/malt-core/protocol"
)

func TestAuthenticationJSONExactFieldNamesAndValues(t *testing.T) {
	root, err := maltcid.NewRoot(maltcid.RootDescriptor{DerivationProfile: uint8(derivation.Direct), Layout: maltcid.Positional, Profile: maltcid.IPA256}, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	prefix := fmt.Sprintf(`{"profile":"malt.authentication/3","root":%q,`, root.String())
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
	for _, raw := range []string{`"YR=="`, `"YQ==\n"`, `null`, `[1,2]`, `{"kind":"label","data":"YQ=="}`} {
		if _, err := protocol.DecodeAuthenticationRequest([]byte(prefix + `"operation":"binding","label":` + raw + `}`)); err == nil {
			t.Fatal("accepted invalid label", raw)
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

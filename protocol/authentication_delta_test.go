package protocol_test

import (
	"testing"

	"github.com/dewebprotocol/malt-core/protocol"
)

func TestAuthenticationDeltaRejectsAmbiguousWireInputs(t *testing.T) {
	for _, data := range []string{
		`{"profile":"malt.authentication-delta/0","changes":[]}`,
		`{"profile":"malt.authentication-delta/0","changes":[],"count":"0"}`,
		`{"profile":"malt.authentication-delta/0","changes":[{"input":{"kind":"index","number":"0"},"after":"bafkqaaa"}],"count":"1"}`,
	} {
		if _, err := protocol.DecodeAuthenticationDelta([]byte(data)); err != nil {
			t.Fatal(data, err)
		}
	}
	for _, data := range []string{
		`{"profile":"malt.authentication-delta/0","changes":null}`,
		`{"profile":"malt.authentication-delta/0","changes":[],"count":null}`,
		`{"profile":"malt.authentication-delta/0","changes":[],"count":"01"}`,
		`{"profile":"malt.authentication-delta/0","changes":[],"count":"18446744073709551616"}`,
		`{"profile":"malt.authentication-delta/0","changes":[],"Changes":[]}`,
		`{"profile":"malt.authentication-delta/0","changes":[],"changes":[]}`,
		`{"profile":"malt.authentication-delta/0","changes":[{"input":{"kind":"index","number":"0"}}]}`,
		`{"profile":"malt.authentication-delta/0","changes":[{"input":{"kind":"index","number":"0"},"after":"invalid"}]}`,
		`{"profile":"malt.authentication-delta/0","changes":[{"input":{"kind":"index","number":"0"},"after":""}]}`,
		`{"profile":"malt.authentication-delta/0","changes":[{"input":{"kind":"index","number":"0"},"before":"","after":"bafkqaaa"}]}`,
	} {
		if _, err := protocol.DecodeAuthenticationDelta([]byte(data)); err == nil {
			t.Fatal("accepted ambiguous delta", data)
		}
	}
}

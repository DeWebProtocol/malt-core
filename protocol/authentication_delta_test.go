package protocol_test

import (
	"testing"

	"github.com/dewebprotocol/malt-core/protocol"
)

func TestAuthenticationDeltaRejectsAmbiguousWireInputs(t *testing.T) {
	for _, data := range []string{
		`{"profile":"malt.authentication-delta/2","changes":[],"payload_cid":""}`,
		`{"profile":"malt.authentication-delta/2","changes":[],"payload_cid":"bafkqaaa"}`,
		`{"profile":"malt.authentication-delta/2","changes":[]}`,
		`{"profile":"malt.authentication-delta/2","changes":[],"count":"0"}`,
		`{"profile":"malt.authentication-delta/2","changes":[{"label":"AAAAAAAAAAA=","after":"bafkqaaa"}],"count":"1"}`,
	} {
		if _, err := protocol.DecodeAuthenticationDelta([]byte(data)); err != nil {
			t.Fatal(data, err)
		}
	}
	for _, data := range []string{
		`{"profile":"malt.authentication-delta/2","changes":[],"payload_cid":null}`,
		`{"profile":"malt.authentication-delta/2","changes":[],"payload_cid":"invalid"}`,
		`{"profile":"malt.authentication-delta/2","changes":[],"total_size":"0"}`,
		`{"profile":"malt.authentication-delta/1","changes":[]}`,
		`{"profile":"malt.authentication-delta/2","changes":null}`,
		`{"profile":"malt.authentication-delta/2","changes":[],"count":null}`,
		`{"profile":"malt.authentication-delta/2","changes":[],"count":"01"}`,
		`{"profile":"malt.authentication-delta/2","changes":[],"count":"18446744073709551616"}`,
		`{"profile":"malt.authentication-delta/2","changes":[],"Changes":[]}`,
		`{"profile":"malt.authentication-delta/2","changes":[],"changes":[]}`,
		`{"profile":"malt.authentication-delta/2","changes":[{"label":"AAAAAAAAAAA="}]}`,
		`{"profile":"malt.authentication-delta/2","changes":[{"label":"AAAAAAAAAAA=","after":"invalid"}]}`,
		`{"profile":"malt.authentication-delta/2","changes":[{"label":"AAAAAAAAAAA=","after":""}]}`,
		`{"profile":"malt.authentication-delta/2","changes":[{"label":"AAAAAAAAAAA=","before":"","after":"bafkqaaa"}]}`,
	} {
		if _, err := protocol.DecodeAuthenticationDelta([]byte(data)); err == nil {
			t.Fatal("accepted ambiguous delta", data)
		}
	}
}

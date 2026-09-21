//go:build js && wasm

package main

import (
	"fmt"
	"syscall/js"

	"github.com/dewebprotocol/malt-core/protocol"
	"github.com/dewebprotocol/malt-core/sdk/authentication"
	authbuiltin "github.com/dewebprotocol/malt-core/sdk/authentication/builtin"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
)

func registerAuthenticationVerifier(backend string) error {
	var profiles []maltcid.ProfileID
	switch backend {
	case "all":
	case "kzg":
		profiles = []maltcid.ProfileID{maltcid.KZG4096}
	case "ipa":
		profiles = []maltcid.ProfileID{maltcid.IPA256}
	default:
		return fmt.Errorf("unsupported verifier backend %q", backend)
	}
	verifier, initErr := authbuiltin.NewVerifier(nil, profiles...)
	if initErr != nil {
		return initErr
	}
	f := js.FuncOf(func(_ js.Value, args []js.Value) any {
		result := protocol.VerificationResult{Profile: protocol.AuthenticationPathProfile}
		if len(args) != 1 || args[0].Type() != js.TypeString {
			result.Error = "maltVerifyAuthentication expects one JSON string"
			return encodeProtocolResponse(result)
		}
		wire, err := protocol.DecodeAuthenticationVerification([]byte(args[0].String()))
		if err != nil {
			result.Error = err.Error()
			return encodeProtocolResponse(result)
		}
		result.Profile = wire.Request.Profile
		result.Valid, err = authentication.Verify(verifier, wire.Request, wire.Result)
		if err != nil {
			result.Error = err.Error()
		}
		return encodeProtocolResponse(result)
	})
	js.Global().Set("maltVerifyAuthentication", f)
	return nil
}

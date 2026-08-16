//go:build js && wasm

// malt-verifier-wasm exposes the portable client verifier to browser clients.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"syscall/js"

	"github.com/dewebprotocol/malt-core/artifact"
	"github.com/dewebprotocol/malt-core/protocol"
	clientverifier "github.com/dewebprotocol/malt-core/sdk/verifier"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
)

func main() {
	backend := requestedBackend()
	verifier, initErr := newVerifier(backend)
	if initErr != nil {
		js.Global().Set("maltVerifierInitError", initErr.Error())
	}
	js.Global().Set("maltVerifierLoadedBackend", backend)
	artifactFunction := js.FuncOf(func(_ js.Value, args []js.Value) any {
		if initErr != nil {
			return encodeResponse(clientverifier.Result{Profile: artifact.Profile, Error: fmt.Sprintf("initialize verifier: %v", initErr)})
		}
		if len(args) != 1 || args[0].Type() != js.TypeString {
			return encodeResponse(clientverifier.Result{Profile: artifact.Profile, Error: "maltVerifyArtifact expects one JSON string"})
		}
		var request clientverifier.Request
		if err := json.Unmarshal([]byte(args[0].String()), &request); err != nil {
			return encodeResponse(clientverifier.Result{Profile: artifact.Profile, Error: fmt.Sprintf("decode verify request: %v", err)})
		}
		if err := verifier.Verify(context.Background(), request); err != nil {
			return encodeResponse(clientverifier.Result{Profile: artifact.Profile, Error: err.Error()})
		}
		return encodeResponse(clientverifier.Result{Profile: artifact.Profile, Valid: true})
	})
	resolveFunction := js.FuncOf(func(_ js.Value, args []js.Value) any {
		if initErr != nil {
			return encodeProtocolResponse(protocol.VerificationResult{Profile: protocol.ResolveProfile, Error: fmt.Sprintf("initialize verifier: %v", initErr)})
		}
		if len(args) != 1 || args[0].Type() != js.TypeString {
			return encodeProtocolResponse(protocol.VerificationResult{Profile: protocol.ResolveProfile, Error: "maltVerifyResolve expects one JSON string"})
		}
		value, err := protocol.DecodeResolveVerification([]byte(args[0].String()))
		if err != nil {
			return encodeProtocolResponse(protocol.VerificationResult{Profile: protocol.ResolveProfile, Error: fmt.Sprintf("decode resolve verification: %v", err)})
		}
		if err := verifier.VerifyResolve(context.Background(), value); err != nil {
			return encodeProtocolResponse(protocol.VerificationResult{Profile: protocol.ResolveProfile, Error: err.Error()})
		}
		return encodeProtocolResponse(protocol.VerificationResult{Profile: protocol.ResolveProfile, Valid: true})
	})
	readFunction := js.FuncOf(func(_ js.Value, args []js.Value) any {
		if initErr != nil {
			return encodeProtocolResponse(protocol.VerificationResult{Profile: protocol.ReadProfile, Error: fmt.Sprintf("initialize verifier: %v", initErr)})
		}
		if len(args) != 1 || args[0].Type() != js.TypeString {
			return encodeProtocolResponse(protocol.VerificationResult{Profile: protocol.ReadProfile, Error: "maltVerifyRead expects one JSON string"})
		}
		value, err := protocol.DecodeReadVerification([]byte(args[0].String()))
		if err != nil {
			return encodeProtocolResponse(protocol.VerificationResult{Profile: protocol.ReadProfile, Error: fmt.Sprintf("decode read verification: %v", err)})
		}
		if err := verifier.VerifyRead(context.Background(), value); err != nil {
			return encodeProtocolResponse(protocol.VerificationResult{Profile: protocol.ReadProfile, Error: err.Error()})
		}
		return encodeProtocolResponse(protocol.VerificationResult{Profile: protocol.ReadProfile, Valid: true})
	})
	mapProofFunction := js.FuncOf(func(_ js.Value, args []js.Value) any {
		if initErr != nil {
			return encodeProtocolResponse(protocol.VerificationResult{Profile: protocol.MapProofProfile, Error: fmt.Sprintf("initialize verifier: %v", initErr)})
		}
		if len(args) != 1 || args[0].Type() != js.TypeString {
			return encodeProtocolResponse(protocol.VerificationResult{Profile: protocol.MapProofProfile, Error: "maltVerifyMapProof expects one JSON string"})
		}
		value, err := protocol.DecodeMapProofVerification([]byte(args[0].String()))
		if err != nil {
			return encodeProtocolResponse(protocol.VerificationResult{Profile: protocol.MapProofProfile, Error: fmt.Sprintf("decode map-proof verification: %v", err)})
		}
		if err := verifier.VerifyMapProof(context.Background(), value); err != nil {
			return encodeProtocolResponse(protocol.VerificationResult{Profile: protocol.MapProofProfile, Error: err.Error()})
		}
		return encodeProtocolResponse(protocol.VerificationResult{Profile: protocol.MapProofProfile, Valid: true})
	})
	js.Global().Set("maltVerifyArtifact", artifactFunction)
	js.Global().Set("maltVerifyMapProof", mapProofFunction)
	js.Global().Set("maltVerifyResolve", resolveFunction)
	js.Global().Set("maltVerifyRead", readFunction)
	select {}
}

func requestedBackend() string {
	value := js.Global().Get("maltVerifierBackend")
	if value.Type() != js.TypeString || value.String() == "" {
		return "all"
	}
	return value.String()
}

func newVerifier(backend string) (*clientverifier.Verifier, error) {
	switch backend {
	case "all":
		return clientverifier.NewDefault()
	case string(maltcid.BackendKindKZG):
		return clientverifier.NewForBackend(maltcid.BackendKindKZG)
	case string(maltcid.BackendKindIPA):
		return clientverifier.NewForBackend(maltcid.BackendKindIPA)
	default:
		return nil, fmt.Errorf("unsupported verifier backend %q", backend)
	}
}

func encodeResponse(response clientverifier.Result) string {
	data, err := json.Marshal(response)
	if err != nil {
		return `{"profile":"malt.artifact/v0alpha2","valid":false,"error":"encode verifier response"}`
	}
	return string(data)
}

func encodeProtocolResponse(response protocol.VerificationResult) string {
	data, err := json.Marshal(response)
	if err != nil {
		return `{"valid":false,"error":"encode verifier response"}`
	}
	return string(data)
}

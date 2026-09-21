//go:build js && wasm

// malt-verifier-wasm exposes the portable client verifier to browser clients.
package main

import (
	"encoding/json"
	"syscall/js"

	"github.com/dewebprotocol/malt-core/protocol"
)

func main() {
	backend := requestedBackend()
	if err := registerAuthenticationVerifier(backend); err != nil {
		js.Global().Set("maltVerifierInitError", err.Error())
	}
	js.Global().Set("maltVerifierLoadedBackend", backend)
	js.Global().Set("maltVerifierReady", true)
	select {}
}

func requestedBackend() string {
	value := js.Global().Get("maltVerifierBackend")
	if value.Type() != js.TypeString || value.String() == "" {
		return "all"
	}
	return value.String()
}

func encodeProtocolResponse(response protocol.VerificationResult) string {
	data, err := json.Marshal(response)
	if err != nil {
		return `{"valid":false,"error":"encode verifier response"}`
	}
	return string(data)
}

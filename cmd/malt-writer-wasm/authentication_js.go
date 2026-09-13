//go:build js && wasm

package main

import (
	"context"
	"syscall/js"

	"github.com/dewebprotocol/malt-core/protocol"
)

func registerAuthenticationWriter(writer *computer, initErr error) {
	f := js.FuncOf(func(_ js.Value, args []js.Value) any {
		promise := js.Global().Get("Promise")
		if initErr != nil {
			return promise.Call("reject", initErr.Error())
		}
		if len(args) != 1 {
			return promise.Call("reject", "maltPrepareAuthentication expects state JSON Uint8Array")
		}
		data, err := copyBoundedBytes(args[0], "authentication state", protocol.MaxVerificationJSONBytes)
		if err != nil {
			return promise.Call("reject", err.Error())
		}
		return promiseString(func() (string, error) {
			result, err := writer.prepareAuthentication(context.Background(), data)
			return string(result), err
		})
	})
	js.Global().Set("maltPrepareAuthentication", f)
}

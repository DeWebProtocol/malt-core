//go:build js && wasm

// malt-writer-wasm exposes exact client-root computation to browser clients.
package main

import (
	"context"
	"fmt"
	writerhost "github.com/dewebprotocol/malt-core/sdk/writer/host"
	"math"
	"syscall/js"

	"github.com/dewebprotocol/malt-core/protocol"
)

const maxTransactionIDBytes = 128

func main() {
	backend, initErr := startupBackend()
	profile := startupProfile(backend)
	var writer *writerhost.Computer
	if initErr == nil {
		writer, initErr = newComputer(backend)
	}
	sessionWriter, sessionInitErr := writerhost.NewSession(writer)
	if initErr == nil && sessionInitErr != nil {
		initErr = sessionInitErr
	}
	if initErr != nil {
		js.Global().Set("maltWriterInitError", initErr.Error())
	}
	js.Global().Set("maltWriterLoadedBackend", backend)
	js.Global().Set("maltWriterLoadedProfile", profile)
	registerStatelessCompute(writer, initErr)
	registerAuthenticationWriter(writer, initErr)
	registerReceiptValidation()
	registerSessionFunctions(sessionWriter, initErr)
	js.Global().Set("maltWriterReady", true)
	select {}
}

func registerStatelessCompute(writer *writerhost.Computer, initErr error) {
	computeFunction := js.FuncOf(func(_ js.Value, args []js.Value) any {
		promise := js.Global().Get("Promise")
		if initErr != nil {
			return promise.Call("reject", fmt.Sprintf("initialize MALT writer: %v", initErr))
		}
		if len(args) != 3 {
			return promise.Call("reject", "maltComputeClientRootV1 expects transaction ID, update-view JSON, and semantic-intent JSON Uint8Arrays")
		}
		transactionIDBytes, err := copyBoundedBytes(args[0], "transaction ID", maxTransactionIDBytes)
		if err != nil {
			return promise.Call("reject", err.Error())
		}
		transactionID := string(transactionIDBytes)
		updateViewJSON, err := copyBoundedBytes(args[1], "update-view JSON", protocol.MaxClientRootJSONBytes)
		if err != nil {
			return promise.Call("reject", err.Error())
		}
		semanticIntentJSON, err := copyBoundedBytes(args[2], "semantic-intent JSON", protocol.MaxClientRootJSONBytes)
		if err != nil {
			return promise.Call("reject", err.Error())
		}
		return promiseString(func() (string, error) {
			result, err := writer.Compute(context.Background(), transactionID, updateViewJSON, semanticIntentJSON)
			return string(result), err
		})
	})
	js.Global().Set("maltComputeClientRootV1", computeFunction)
}

func registerReceiptValidation() {
	validateFunction := js.FuncOf(func(_ js.Value, args []js.Value) any {
		promise := js.Global().Get("Promise")
		if len(args) != 2 {
			return promise.Call("reject", "maltWriterValidateReceiptV1 expects writer-result and materialization-receipt JSON Uint8Arrays")
		}
		resultJSON, err := copyBoundedBytes(args[0], "writer-result JSON", protocol.MaxClientRootJSONBytes)
		if err != nil {
			return promise.Call("reject", err.Error())
		}
		receiptJSON, err := copyBoundedBytes(args[1], "materialization-receipt JSON", protocol.MaxClientRootJSONBytes)
		if err != nil {
			return promise.Call("reject", err.Error())
		}
		return promiseString(func() (string, error) {
			return writerhost.ValidateMaterializationReceipt(resultJSON, receiptJSON)
		})
	})
	js.Global().Set("maltWriterValidateReceiptV1", validateFunction)
}

func registerSessionFunctions(writer *writerhost.Session, initErr error) {
	prepareGate := make(chan struct{}, 1)
	bootstrapFunction := js.FuncOf(func(_ js.Value, args []js.Value) any {
		promise := js.Global().Get("Promise")
		if initErr != nil {
			return promise.Call("reject", fmt.Sprintf("initialize MALT writer session: %v", initErr))
		}
		if len(args) != 0 {
			return promise.Call("reject", "maltWriterBootstrapSessionV1 expects no arguments")
		}
		return promiseString(func() (string, error) {
			result, err := writer.Bootstrap(context.Background())
			return string(result), err
		})
	})
	js.Global().Set("maltWriterBootstrapSessionV1", bootstrapFunction)

	loadFunction := js.FuncOf(func(_ js.Value, args []js.Value) any {
		promise := js.Global().Get("Promise")
		if initErr != nil {
			return promise.Call("reject", fmt.Sprintf("initialize MALT writer session: %v", initErr))
		}
		if len(args) != 1 {
			return promise.Call("reject", "maltWriterLoadSessionV1 expects update-view JSON Uint8Array")
		}
		updateViewJSON, err := copyBoundedBytes(args[0], "update-view JSON", protocol.MaxClientRootJSONBytes)
		if err != nil {
			return promise.Call("reject", err.Error())
		}
		return promiseString(func() (string, error) {
			return writer.Load(context.Background(), updateViewJSON)
		})
	})
	js.Global().Set("maltWriterLoadSessionV1", loadFunction)

	prepareFunction := js.FuncOf(func(_ js.Value, args []js.Value) any {
		promise := js.Global().Get("Promise")
		if initErr != nil {
			return promise.Call("reject", fmt.Sprintf("initialize MALT writer session: %v", initErr))
		}
		if len(args) != 2 {
			return promise.Call("reject", "maltWriterPrepareSessionV1 expects transaction ID and semantic-intent JSON Uint8Arrays")
		}
		select {
		case prepareGate <- struct{}{}:
		default:
			return promise.Call("reject", "a client writer session prepare is already in flight")
		}
		releasePrepare := func() { <-prepareGate }
		transactionIDBytes, err := copyBoundedBytes(args[0], "transaction ID", maxTransactionIDBytes)
		if err != nil {
			releasePrepare()
			return promise.Call("reject", err.Error())
		}
		intentJSON, err := copyBoundedBytes(args[1], "semantic-intent JSON", protocol.MaxClientRootJSONBytes)
		if err != nil {
			releasePrepare()
			return promise.Call("reject", err.Error())
		}
		transactionID := string(transactionIDBytes)
		return promiseStringFinally(func() (string, error) {
			return writer.Prepare(context.Background(), transactionID, intentJSON)
		}, releasePrepare)
	})
	js.Global().Set("maltWriterPrepareSessionV1", prepareFunction)

	getPreparedResultFunction := js.FuncOf(func(_ js.Value, args []js.Value) any {
		promise := js.Global().Get("Promise")
		if initErr != nil {
			return promise.Call("reject", fmt.Sprintf("initialize MALT writer session: %v", initErr))
		}
		if len(args) != 1 {
			return promise.Call("reject", "maltWriterGetPreparedResultV1 expects an transaction ID Uint8Array")
		}
		transactionIDBytes, err := copyBoundedBytes(args[0], "transaction ID", maxTransactionIDBytes)
		if err != nil {
			return promise.Call("reject", err.Error())
		}
		transactionID := string(transactionIDBytes)
		return promiseString(func() (string, error) {
			result, err := writer.PreparedResult(transactionID)
			return string(result), err
		})
	})
	js.Global().Set("maltWriterGetPreparedResultV1", getPreparedResultFunction)

	acceptFunction := js.FuncOf(func(_ js.Value, args []js.Value) any {
		promise := js.Global().Get("Promise")
		if initErr != nil {
			return promise.Call("reject", fmt.Sprintf("initialize MALT writer session: %v", initErr))
		}
		if len(args) != 2 {
			return promise.Call("reject", "maltWriterAcceptSessionReceiptV1 expects transaction ID and materialization-receipt JSON Uint8Arrays")
		}
		transactionIDBytes, err := copyBoundedBytes(args[0], "transaction ID", maxTransactionIDBytes)
		if err != nil {
			return promise.Call("reject", err.Error())
		}
		receiptJSON, err := copyBoundedBytes(args[1], "materialization-receipt JSON", protocol.MaxClientRootJSONBytes)
		if err != nil {
			return promise.Call("reject", err.Error())
		}
		transactionID := string(transactionIDBytes)
		return promiseString(func() (string, error) {
			return writer.AcceptReceipt(transactionID, receiptJSON)
		})
	})
	js.Global().Set("maltWriterAcceptSessionReceiptV1", acceptFunction)

	discardFunction := js.FuncOf(func(_ js.Value, args []js.Value) any {
		promise := js.Global().Get("Promise")
		if initErr != nil {
			return promise.Call("reject", fmt.Sprintf("initialize MALT writer session: %v", initErr))
		}
		if len(args) != 1 {
			return promise.Call("reject", "maltWriterDiscardSessionCandidateV1 expects an transaction ID Uint8Array")
		}
		transactionIDBytes, err := copyBoundedBytes(args[0], "transaction ID", maxTransactionIDBytes)
		if err != nil {
			return promise.Call("reject", err.Error())
		}
		transactionID := string(transactionIDBytes)
		return promiseString(func() (string, error) {
			if err := writer.Discard(transactionID); err != nil {
				return "", err
			}
			return transactionID, nil
		})
	})
	js.Global().Set("maltWriterDiscardSessionCandidateV1", discardFunction)

	closeFunction := js.FuncOf(func(_ js.Value, args []js.Value) any {
		promise := js.Global().Get("Promise")
		if initErr != nil {
			return promise.Call("reject", fmt.Sprintf("initialize MALT writer session: %v", initErr))
		}
		if len(args) != 0 {
			return promise.Call("reject", "maltWriterCloseSessionV1 expects no arguments")
		}
		return promiseString(func() (string, error) {
			writer.Close()
			return "", nil
		})
	})
	js.Global().Set("maltWriterCloseSessionV1", closeFunction)
}

func promiseString(task func() (string, error)) any {
	return promiseStringFinally(task, func() {})
}

func promiseStringFinally(task func() (string, error), finally func()) any {
	promise := js.Global().Get("Promise")
	var executor js.Func
	executor = js.FuncOf(func(_ js.Value, callbacks []js.Value) any {
		resolve, reject := callbacks[0], callbacks[1]
		go func() {
			defer finally()
			result, err := task()
			if err != nil {
				reject.Invoke(err.Error())
				return
			}
			resolve.Invoke(result)
		}()
		return nil
	})
	value := promise.New(executor)
	executor.Release()
	return value
}

func copyBoundedBytes(value js.Value, label string, maxBytes int) ([]byte, error) {
	uint8Array := js.Global().Get("Uint8Array")
	arrayBuffer := js.Global().Get("ArrayBuffer")
	if uint8Array.Type() != js.TypeFunction ||
		arrayBuffer.Type() != js.TypeFunction ||
		value.Type() != js.TypeObject ||
		!arrayBuffer.Call("isView", value).Bool() ||
		!value.InstanceOf(uint8Array) {
		return nil, fmt.Errorf("%s must be a Uint8Array", label)
	}

	object := js.Global().Get("Object")
	typedArrayPrototype := object.Call("getPrototypeOf", uint8Array.Get("prototype"))
	byteLengthGetter := object.Call("getOwnPropertyDescriptor", typedArrayPrototype, "byteLength").Get("get")
	byteOffsetGetter := object.Call("getOwnPropertyDescriptor", typedArrayPrototype, "byteOffset").Get("get")
	bufferGetter := object.Call("getOwnPropertyDescriptor", typedArrayPrototype, "buffer").Get("get")
	sizeNumber := byteLengthGetter.Call("call", value).Float()
	if math.IsNaN(sizeNumber) || math.IsInf(sizeNumber, 0) || math.Trunc(sizeNumber) != sizeNumber {
		return nil, fmt.Errorf("%s has an invalid byte length", label)
	}
	if sizeNumber < 1 {
		return nil, fmt.Errorf("%s is empty", label)
	}
	if sizeNumber > float64(maxBytes) {
		return nil, fmt.Errorf("%s exceeds %d bytes", label, maxBytes)
	}
	offsetNumber := byteOffsetGetter.Call("call", value).Float()
	if math.IsNaN(offsetNumber) || math.IsInf(offsetNumber, 0) ||
		math.Trunc(offsetNumber) != offsetNumber || offsetNumber < 0 {
		return nil, fmt.Errorf("%s has an invalid byte offset", label)
	}
	size := int(sizeNumber)
	buffer := bufferGetter.Call("call", value)
	canonicalView := uint8Array.New(buffer, offsetNumber, sizeNumber)
	data := make([]byte, size)
	if copied := js.CopyBytesToGo(data, canonicalView); copied != size {
		return nil, fmt.Errorf("copy %s: copied %d of %d bytes", label, copied, size)
	}
	return data, nil
}

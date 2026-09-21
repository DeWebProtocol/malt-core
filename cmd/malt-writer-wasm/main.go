//go:build js && wasm

// malt-writer-wasm exposes typed authentication writers to browser clients.
package main

import (
	"fmt"
	writerhost "github.com/dewebprotocol/malt-core/sdk/authentication/host"
	"math"
	"syscall/js"
)

func main() {
	backend, initErr := startupBackend()
	profile := startupProfile(backend)
	var writer *writerhost.Computer
	if initErr == nil {
		writer, initErr = newComputer(backend)
	}
	if initErr != nil {
		js.Global().Set("maltWriterInitError", initErr.Error())
	}
	js.Global().Set("maltWriterLoadedBackend", backend)
	js.Global().Set("maltWriterLoadedProfile", profile)
	registerAuthenticationWriter(writer, initErr)
	js.Global().Set("maltWriterReady", true)
	select {}
}

func promiseString(task func() (string, error)) any {
	promise := js.Global().Get("Promise")
	executor := js.FuncOf(func(_ js.Value, callbacks []js.Value) any {
		resolve, reject := callbacks[0], callbacks[1]
		go func() {
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

//go:build js && wasm

package main

import (
	"context"
	"fmt"
	"syscall/js"

	"github.com/dewebprotocol/malt-core/protocol"
	writerhost "github.com/dewebprotocol/malt-core/sdk/authentication/host"
)

func registerAuthenticationWriter(writer *writerhost.Computer, initErr error) {
	type operation struct {
		name   string
		bounds []int
		run    func(context.Context, [][]byte) ([]byte, error)
	}
	operations := []operation{
		{"maltValidateAuthenticationBatch", []int{protocol.MaxVerificationJSONBytes}, func(ctx context.Context, a [][]byte) ([]byte, error) { return writer.ValidateBatch(ctx, a[0]) }},
		{"maltValidateAuthenticationReceipt", []int{protocol.MaxVerificationJSONBytes, protocol.MaxVerificationJSONBytes}, func(_ context.Context, a [][]byte) ([]byte, error) { return writerhost.ValidateReceipt(a[0], a[1]) }},
		{"maltPrepareAuthentication", []int{protocol.MaxVerificationJSONBytes}, func(ctx context.Context, a [][]byte) ([]byte, error) { return writer.PrepareAuthentication(ctx, a[0]) }},
		{"maltUpdateAuthentication", []int{protocol.MaxVerificationJSONBytes, protocol.MaxVerificationJSONBytes}, func(ctx context.Context, a [][]byte) ([]byte, error) {
			return writer.UpdateAuthentication(ctx, a[0], a[1])
		}},
		{"maltCreateAuthentication", []int{protocol.MaxVerificationJSONBytes}, func(ctx context.Context, a [][]byte) ([]byte, error) { return writer.CreateAuthentication(ctx, a[0]) }},
		{"maltImportAuthentication", []int{protocol.MaxVerificationJSONBytes}, func(ctx context.Context, a [][]byte) ([]byte, error) { return writer.ImportAuthentication(ctx, a[0]) }},
		{"maltApplyAuthentication", []int{20, protocol.MaxVerificationJSONBytes}, func(ctx context.Context, a [][]byte) ([]byte, error) {
			return writer.ApplyAuthentication(ctx, string(a[0]), a[1])
		}},
		{"maltExportAuthentication", []int{20}, func(ctx context.Context, a [][]byte) ([]byte, error) {
			return writer.ExportAuthentication(ctx, string(a[0]))
		}},
		{"maltDiscardAuthentication", []int{20}, func(_ context.Context, a [][]byte) ([]byte, error) {
			return nil, writer.DiscardAuthentication(string(a[0]))
		}},
		{"maltCloseAuthentication", nil, func(_ context.Context, _ [][]byte) ([]byte, error) { return nil, writer.CloseAuthentication() }},
	}
	for _, op := range operations {
		callback := js.FuncOf(func(_ js.Value, args []js.Value) any {
			promise := js.Global().Get("Promise")
			if initErr != nil {
				return promise.Call("reject", initErr.Error())
			}
			if len(args) != len(op.bounds) {
				return promise.Call("reject", fmt.Sprintf("%s expects %d Uint8Array arguments", op.name, len(op.bounds)))
			}
			data := make([][]byte, len(args))
			for i, arg := range args {
				var err error
				data[i], err = copyBoundedBytes(arg, fmt.Sprintf("%s argument %d", op.name, i), op.bounds[i])
				if err != nil {
					return promise.Call("reject", err.Error())
				}
			}
			return promiseString(func() (string, error) { result, err := op.run(context.Background(), data); return string(result), err })
		})
		js.Global().Set(op.name, callback)
	}
}

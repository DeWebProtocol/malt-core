package writer_test

import (
	"runtime"
	"testing"
	"weak"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/graph/writer"
)

//go:noinline
func releasedMaterializer() weak.Pointer[memory.Store] {
	store := memory.New(false)
	w := writer.NewWriter(nil, store)
	ref := weak.Make(store)
	runtime.KeepAlive(w)
	return ref
}

func TestWriterDoesNotRetainReleasedMaterializers(t *testing.T) {
	ref := releasedMaterializer()
	for range 3 {
		runtime.GC()
		if ref.Value() == nil {
			return
		}
	}
	t.Fatal("a discarded Writer still retains its caller-owned materializer")
}

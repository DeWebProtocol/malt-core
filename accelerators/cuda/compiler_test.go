//go:build amd64 && (linux || windows)

package cuda

import (
	"os"
	"testing"
)

// NVRTC supports compilation without a GPU/driver. This opt-in check exercises
// the actual Go FFI and compiled CUDA source, independently of device execution.
func TestNVRTCCompilation(t *testing.T) {
	compiler := os.Getenv("MALT_CUDA_NVRTC_LIBRARY")
	include := os.Getenv("MALT_CUDA_ICICLE_INCLUDE")
	if compiler == "" || include == "" {
		t.Skip("set MALT_CUDA_NVRTC_LIBRARY and MALT_CUDA_ICICLE_INCLUDE for native NVRTC compilation")
	}
	source, err := mathSource(include)
	if err != nil {
		t.Fatal(err)
	}
	d := &driver{}
	defer d.close()
	if err := d.loadCompiler(compiler); err != nil {
		t.Fatal(err)
	}
	ptx, err := d.compile(source, 8, 6)
	if err != nil {
		t.Fatal(err)
	}
	if len(ptx) == 0 {
		t.Fatal("empty PTX")
	}
}

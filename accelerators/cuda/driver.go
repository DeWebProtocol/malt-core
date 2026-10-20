//go:build amd64 && (linux || windows)

package cuda

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"github.com/ebitengine/purego"
)

// Exact CUDA Driver/NVRTC C ABI; no structs are passed by value. All Go host
// buffers are consumed synchronously. Asynchronous copies use driver-allocated
// pinned memory; kernels only retain CUDA device addresses.
type driver struct {
	init           func(uint32) int32
	deviceGet      func(*int32, int32) int32
	attribute      func(*int32, int32, int32) int32
	create         func(*uintptr, uint32, int32) int32
	destroy        func(uintptr) int32
	sync           func() int32
	load           func(*uintptr, *byte) int32
	unload         func(uintptr) int32
	function       func(*uintptr, uintptr, string) int32
	alloc          func(*uint64, uintptr) int32
	free           func(uint64) int32
	memory         func(*uintptr, *uintptr) int32
	hostAlloc      func(*unsafe.Pointer, uintptr, uint32) int32
	hostFree       func(unsafe.Pointer) int32
	toDevice       func(uint64, *byte, uintptr) int32
	toDeviceAsync  func(uint64, unsafe.Pointer, uintptr, uintptr) int32
	toHostAsync    func(unsafe.Pointer, uint64, uintptr, uintptr) int32
	streamCreate   func(*uintptr, uint32) int32
	streamDestroy  func(uintptr) int32
	streamSync     func(uintptr) int32
	launch         func(uintptr, uint32, uint32, uint32, uint32, uint32, uint32, uint32, uintptr, *unsafe.Pointer, unsafe.Pointer) int32
	createProgram  func(*uintptr, string, string, int32, unsafe.Pointer, unsafe.Pointer) int32
	compileProgram func(uintptr, int32, *unsafe.Pointer) int32
	programLogSize func(uintptr, *uintptr) int32
	programLog     func(uintptr, *byte) int32
	ptxSize        func(uintptr, *uintptr) int32
	ptx            func(uintptr, *byte) int32
	destroyProgram func(*uintptr) int32
	libraries      []uintptr
}

func check(code int32, operation string) error {
	if code != 0 {
		return fmt.Errorf("%s returned CUDA/NVRTC status %d", operation, code)
	}
	return nil
}

func loadDriver(nvrtc string) (d *driver, err error) {
	d = &driver{}
	defer func() {
		if err != nil {
			_ = d.close()
		}
	}()
	lib, err := openLibrary(driverLibrary())
	if err != nil {
		return d, fmt.Errorf("load NVIDIA driver: %w", err)
	}
	d.libraries = append(d.libraries, lib)
	for _, entry := range []struct {
		name string
		fn   any
	}{
		{"cuInit", &d.init}, {"cuDeviceGet", &d.deviceGet}, {"cuDeviceGetAttribute", &d.attribute},
		{"cuCtxCreate_v2", &d.create}, {"cuCtxDestroy_v2", &d.destroy}, {"cuCtxSynchronize", &d.sync},
		{"cuModuleLoadData", &d.load}, {"cuModuleUnload", &d.unload}, {"cuModuleGetFunction", &d.function},
		{"cuMemAlloc_v2", &d.alloc}, {"cuMemFree_v2", &d.free}, {"cuMemGetInfo_v2", &d.memory},
		{"cuMemcpyHtoDAsync_v2", &d.toDeviceAsync}, {"cuMemHostAlloc", &d.hostAlloc}, {"cuMemFreeHost", &d.hostFree}, {"cuMemcpyHtoD_v2", &d.toDevice}, {"cuMemcpyDtoHAsync_v2", &d.toHostAsync},
		{"cuStreamCreate", &d.streamCreate}, {"cuStreamDestroy_v2", &d.streamDestroy}, {"cuStreamSynchronize", &d.streamSync}, {"cuLaunchKernel", &d.launch},
	} {
		if err = bind(lib, entry.name, entry.fn); err != nil {
			return d, err
		}
	}
	if err = d.loadCompiler(nvrtc); err != nil {
		return d, err
	}
	return d, nil
}

func bind(h uintptr, name string, target any) error {
	address, err := librarySymbol(h, name)
	if err != nil {
		return fmt.Errorf("CUDA symbol %s: %w", name, err)
	}
	purego.RegisterFunc(target, address)
	return nil
}

func (d *driver) loadCompiler(nvrtc string) (err error) {
	names := nvrtcLibraries()
	if nvrtc != "" {
		names = []string{nvrtc}
	}
	var failures []error
	var compiler uintptr
	for _, name := range names {
		compiler, err = openLibrary(name)
		if err == nil {
			break
		}
		failures = append(failures, err)
	}
	if compiler == 0 {
		return fmt.Errorf("load NVRTC (set Config.NVRTCLibrary to its absolute DLL/SO path): %w", errors.Join(failures...))
	}
	d.libraries = append(d.libraries, compiler)
	for _, entry := range []struct {
		name string
		fn   any
	}{
		{"nvrtcCreateProgram", &d.createProgram}, {"nvrtcCompileProgram", &d.compileProgram},
		{"nvrtcGetProgramLogSize", &d.programLogSize}, {"nvrtcGetProgramLog", &d.programLog},
		{"nvrtcGetPTXSize", &d.ptxSize}, {"nvrtcGetPTX", &d.ptx}, {"nvrtcDestroyProgram", &d.destroyProgram},
	} {
		if err = bind(compiler, entry.name, entry.fn); err != nil {
			return err
		}
	}
	return nil
}

func (d *driver) close() error {
	var errs []error
	for i := len(d.libraries) - 1; i >= 0; i-- {
		errs = append(errs, closeLibrary(d.libraries[i]))
	}
	d.libraries = nil
	return errors.Join(errs...)
}

func (d *driver) compile(source string, major, minor int32) ([]byte, error) {
	// Retain pinned source through program destruction, independent of NVRTC's
	// internal source ownership. Null termination avoids purego temporary copies.
	source += "\x00"
	var pin runtime.Pinner
	pin.Pin(unsafe.StringData(source))
	defer pin.Unpin()
	var program uintptr
	if err := check(d.createProgram(&program, source, "malt_kzg.cu\x00", 0, nil, nil), "nvrtcCreateProgram"); err != nil {
		return nil, err
	}
	defer d.destroyProgram(&program)
	options := []string{"--std=c++17\x00", "--device-as-default-execution-space\x00", fmt.Sprintf("--gpu-architecture=compute_%d%d\x00", major, minor)}
	ptrs := make([]unsafe.Pointer, len(options))
	for i := range options {
		ptrs[i] = unsafe.Pointer(unsafe.StringData(options[i]))
	}
	code := d.compileProgram(program, int32(len(ptrs)), &ptrs[0])
	runtime.KeepAlive(options)
	if code != 0 {
		var size uintptr
		_ = d.programLogSize(program, &size)
		if size == 0 || size > 16<<20 {
			return nil, check(code, "nvrtcCompileProgram")
		}
		log := make([]byte, size)
		_ = d.programLog(program, &log[0])
		return nil, fmt.Errorf("%w: %s", check(code, "nvrtcCompileProgram"), log)
	}
	var size uintptr
	if err := check(d.ptxSize(program, &size), "nvrtcGetPTXSize"); err != nil {
		return nil, err
	}
	if size == 0 || size > 64<<20 {
		return nil, errors.New("invalid NVRTC PTX size")
	}
	ptx := make([]byte, size)
	if err := check(d.ptx(program, &ptx[0]), "nvrtcGetPTX"); err != nil {
		return nil, err
	}
	return ptx, nil
}

// Parameter memory is pinned until cuLaunchKernel returns. CUDA copies argument
// values during this call; the kernel retains only the device addresses.
func (d *driver) kernel(fn uintptr, gx, gy, threads int, stream uintptr, values ...uint64) error {
	ptrs := make([]unsafe.Pointer, len(values))
	var pin runtime.Pinner
	defer pin.Unpin()
	for i := range values {
		pin.Pin(&values[i])
		ptrs[i] = unsafe.Pointer(&values[i])
	}
	pin.Pin(&ptrs[0])
	err := check(d.launch(fn, uint32(gx), uint32(gy), 1, uint32(threads), 1, 1, 0, stream, &ptrs[0], nil), "cuLaunchKernel")
	runtime.KeepAlive(values)
	return err
}

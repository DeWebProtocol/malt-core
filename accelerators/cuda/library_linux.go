//go:build linux && amd64

package cuda

import "github.com/ebitengine/purego"

func openLibrary(name string) (uintptr, error) {
	return purego.Dlopen(name, purego.RTLD_NOW|purego.RTLD_LOCAL)
}
func closeLibrary(handle uintptr) error                          { return purego.Dlclose(handle) }
func librarySymbol(handle uintptr, name string) (uintptr, error) { return purego.Dlsym(handle, name) }
func driverLibrary() string                                      { return "libcuda.so.1" }
func nvrtcLibraries() []string                                   { return []string{"libnvrtc.so", "libnvrtc.so.13", "libnvrtc.so.12"} }

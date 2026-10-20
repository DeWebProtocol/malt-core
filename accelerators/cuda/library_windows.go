//go:build windows && amd64

package cuda

import (
	"os"
	"path/filepath"
	"syscall"
)

func openLibrary(name string) (uintptr, error) {
	h, err := syscall.LoadLibrary(name)
	return uintptr(h), err
}
func closeLibrary(handle uintptr) error { return syscall.FreeLibrary(syscall.Handle(handle)) }
func librarySymbol(handle uintptr, name string) (uintptr, error) {
	return syscall.GetProcAddress(syscall.Handle(handle), name)
}
func driverLibrary() string { return filepath.Join(os.Getenv("SystemRoot"), "System32", "nvcuda.dll") }
func nvrtcLibraries() []string {
	var names []string
	if root := os.Getenv("CUDA_PATH"); root != "" {
		for _, name := range []string{"nvrtc64_130_0.dll", "nvrtc64_120_0.dll"} {
			names = append(names, filepath.Join(root, "bin", name))
		}
	}
	return names
}

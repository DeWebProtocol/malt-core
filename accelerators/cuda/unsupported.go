//go:build !amd64 || (!linux && !windows)

package cuda

import "errors"

func newDevice(Config, string, []byte) (device, error) {
	return nil, errors.New("CUDA opening supports Linux/amd64 and Windows/amd64")
}

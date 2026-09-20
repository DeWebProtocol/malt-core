// Package resolver implements path resolution with prefix consumption across
// native MALT structure roots and terminal content CIDs.

package resolver

import "errors"

// Sentinel errors for resolver operations.
var (
	// ErrUndefinedRoot is returned when the root CID is undefined.
	ErrUndefinedRoot = errors.New("root is not defined")

	// ErrResolutionFailed is returned when a resolution step fails.
	ErrResolutionFailed = errors.New("resolution failed")
)

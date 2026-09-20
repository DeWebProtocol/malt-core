// Package commitment defines abstract interfaces for cryptographic commitment schemes.
package commitment

import "errors"

// Sentinel errors for commitment operations.
var (
	// ErrInvalidCommitment is returned when a commitment value is malformed or invalid.
	ErrInvalidCommitment = errors.New("invalid commitment")
)

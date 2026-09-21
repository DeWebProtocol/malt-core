package protocol

// VerificationResult is the verdict returned by the portable WASM verifier.
type VerificationResult struct {
	Profile string `json:"profile"`
	Valid   bool   `json:"valid"`
	Error   string `json:"error,omitempty"`
}

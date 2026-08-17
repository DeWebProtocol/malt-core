package verifier

import (
	"fmt"

	"github.com/dewebprotocol/malt-core/artifact"
	cid "github.com/ipfs/go-cid"
)

// Expectation contains the operation inputs selected by the caller before it
// accepts an untrusted artifact. Target is optional because resolve/prove
// callers normally learn the authenticated target from the result.
type Expectation struct {
	Operation artifact.Operation `json:"operation"`
	Query     artifact.Query     `json:"query"`
	Target    string             `json:"target,omitempty"`
}

// Request is the local-verifier envelope. TrustedRoot and Expected are
// separate from the untrusted artifact so the cryptographic boundary cannot
// silently adopt a root, operation, query, or optional target supplied by the
// resolver/gateway.
type Request struct {
	Profile     string            `json:"profile"`
	TrustedRoot string            `json:"trusted_root"`
	Expected    Expectation       `json:"expected"`
	Artifact    artifact.Artifact `json:"artifact"`
}

type Result struct {
	Profile string `json:"profile"`
	Valid   bool   `json:"valid"`
	Error   string `json:"error,omitempty"`
}

func (r Request) Validate() error {
	if r.Profile != artifact.Profile {
		return fmt.Errorf("unsupported local verifier profile %q", r.Profile)
	}
	root, err := cid.Decode(r.TrustedRoot)
	if err != nil {
		return fmt.Errorf("invalid trusted root: %w", err)
	}
	if err := r.Artifact.Validate(); err != nil {
		return err
	}
	if err := r.Expected.Validate(); err != nil {
		return err
	}
	if r.Artifact.Root != root.String() {
		return fmt.Errorf("artifact root %q does not match trusted root %s", r.Artifact.Root, root)
	}
	if r.Artifact.Operation != r.Expected.Operation {
		return fmt.Errorf("artifact operation %q does not match expected operation %q", r.Artifact.Operation, r.Expected.Operation)
	}
	if !r.Artifact.Query.Equal(r.Expected.Query) {
		return fmt.Errorf("artifact query does not match expected query")
	}
	if r.Expected.Target != "" && r.Artifact.Target != r.Expected.Target {
		return fmt.Errorf("artifact target %q does not match expected target %q", r.Artifact.Target, r.Expected.Target)
	}
	return nil
}

// Validate checks the independently selected expectation without consulting
// artifact fields.
func (e Expectation) Validate() error {
	switch e.Operation {
	case artifact.OperationResolve:
		if err := e.Query.Validate(true); err != nil {
			return fmt.Errorf("invalid expected resolve query: %w", err)
		}
		if e.Query.Kind != artifact.QueryPath {
			return fmt.Errorf("expected resolve operation must use a path query")
		}
	case artifact.OperationProve:
		if err := e.Query.Validate(false); err != nil {
			return fmt.Errorf("invalid expected prove query: %w", err)
		}
	default:
		return fmt.Errorf("unsupported expected operation %q", e.Operation)
	}
	if e.Target != "" {
		if _, err := cid.Parse(e.Target); err != nil {
			return fmt.Errorf("invalid expected target CID: %w", err)
		}
	}
	return nil
}

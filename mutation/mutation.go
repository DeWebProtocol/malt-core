// Package mutation defines the application-neutral MALT mutation and receipt
// contracts. The package contains value types and validation only; applying a
// mutation, choosing a materialization namespace, and publishing a result root
// belong to an execution backend.
package mutation

import (
	"errors"
	"fmt"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

var (
	// ErrInvalidBaseRoot is returned when an update mutation has no base root.
	ErrInvalidBaseRoot = errors.New("invalid base root")
	// ErrEmptyDeltas is returned when a semantic mutation carries no arc deltas.
	ErrEmptyDeltas = errors.New("empty deltas")
	// ErrObjectKindMismatch is returned when a delta kind disagrees with its object or changes kind.
	ErrObjectKindMismatch = errors.New("object kind mismatch")
	// ErrNilDelta is returned when a mutation has no canonical delta.
	ErrNilDelta = errors.New("nil delta")
	// ErrExpectedRootMismatch is returned when an executor does not reproduce
	// the result root declared by a mutation plan.
	ErrExpectedRootMismatch = errors.New("expected root mismatch")
)

// SemanticMutation is the portable mutation boundary emitted by clients and
// application adapters. It deliberately carries no namespace, tenant, storage,
// or publication policy.
type SemanticMutation struct {
	BaseRoot cid.Cid
	Deltas   []ArcSetDelta
}

// ArcSetDelta applies coordinate-level changes to one semantic object.
type ArcSetDelta struct {
	Object       cid.Cid
	ExpectedRoot cid.Cid
	Kind         arcset.Kind
	Changes      *arcset.CanonicalArcDelta
	Commit       CommitDescriptor
}

// CommitDescriptor records how a logical canonical arcset should be committed
// into a concrete semantic root. The zero value is the default map/list commit.
type CommitDescriptor struct {
	FixedList *FixedListCommit
}

// FixedListCommit describes the measured fixed-width list commit profile.
type FixedListCommit struct {
	TotalSize uint64
	ChunkSize uint64
}

// WriteReceipt records the execution result without publishing or authorizing
// the returned root.
type WriteReceipt struct {
	BaseRoot   cid.Cid
	NewRoot    cid.Cid
	DeltaCount int
	ArcCount   int
}

// Validate validates the portable shape of a semantic mutation.
func Validate(mut SemanticMutation) error {
	if !mut.BaseRoot.Defined() {
		return ErrInvalidBaseRoot
	}
	if len(mut.Deltas) == 0 {
		return ErrEmptyDeltas
	}
	for i, delta := range mut.Deltas {
		if delta.Changes == nil {
			return fmt.Errorf("delta %d: %w", i, ErrNilDelta)
		}
		if delta.Kind != delta.Changes.Kind() {
			return fmt.Errorf("delta %d: %w", i, ErrObjectKindMismatch)
		}
		if !objectKindMatches(delta.Object, delta.Kind) {
			return fmt.Errorf("delta %d: %w", i, ErrObjectKindMismatch)
		}
		if !objectKindMatches(delta.ExpectedRoot, delta.Kind) {
			return fmt.Errorf("delta %d expected root: %w", i, ErrObjectKindMismatch)
		}
		if delta.Commit.FixedList != nil && delta.Kind != arcset.KindList {
			return fmt.Errorf("delta %d fixed list commit on %q: %w", i, delta.Kind, ErrObjectKindMismatch)
		}
	}
	return nil
}

func objectKindMatches(object cid.Cid, kind arcset.Kind) bool {
	if !object.Defined() {
		return true
	}

	switch maltcid.SemanticKindOf(object) {
	case maltcid.SemanticKindUnknown:
		return true
	case maltcid.SemanticKindMap:
		return kind == arcset.KindMap
	case maltcid.SemanticKindList:
		return kind == arcset.KindList
	default:
		return false
	}
}

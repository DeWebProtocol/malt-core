// Package writer implements graph semantic mutations.
package writer

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	"github.com/dewebprotocol/malt-core/auth/semantic/list"
	"github.com/dewebprotocol/malt-core/auth/semantic/mapping"
	coremutation "github.com/dewebprotocol/malt-core/mutation"
	cid "github.com/ipfs/go-cid"
)

var (
	// ErrInvalidNamespace is returned when an executor has no internal materialization namespace.
	ErrInvalidNamespace = errors.New("invalid materialization namespace")

	// Deprecated: use the corresponding portable sentinel in package mutation.
	ErrInvalidBaseRoot = coremutation.ErrInvalidBaseRoot
	// Deprecated: use the corresponding portable sentinel in package mutation.
	ErrEmptyDeltas = coremutation.ErrEmptyDeltas
	// Deprecated: use the corresponding portable sentinel in package mutation.
	ErrObjectKindMismatch = coremutation.ErrObjectKindMismatch
	// Deprecated: use the corresponding portable sentinel in package mutation.
	ErrNilDelta = coremutation.ErrNilDelta
	// Deprecated: use the corresponding portable sentinel in package mutation.
	ErrExpectedRootMismatch = coremutation.ErrExpectedRootMismatch
)

// Deprecated: import package mutation for portable contract types.
type SemanticMutation = coremutation.SemanticMutation

// Deprecated: import package mutation for portable contract types.
type ArcSetDelta = coremutation.ArcSetDelta

// Deprecated: import package mutation for portable contract types.
type CommitDescriptor = coremutation.CommitDescriptor

// Deprecated: import package mutation for portable contract types.
type FixedListCommit = coremutation.FixedListCommit

// Deprecated: import package mutation for portable contract types.
type WriteReceipt = coremutation.WriteReceipt

// ValidateSemanticMutation validates the shape of an update semantic mutation.
func ValidateSemanticMutation(mut SemanticMutation) error {
	return coremutation.Validate(mut)
}

// Apply commits canonical arc deltas in order.
//
// The executor treats BaseRoot as the caller's update base for receipt and
// validation purposes only. It does not publish heads, arbitrate freshness, or
// merge concurrent roots.
func (w *Writer) Apply(ctx context.Context, namespace string, mut SemanticMutation) (WriteReceipt, error) {
	if namespace == "" {
		return WriteReceipt{}, ErrInvalidNamespace
	}
	if err := ValidateSemanticMutation(mut); err != nil {
		return WriteReceipt{}, err
	}

	var newRoot cid.Cid
	arcCount := 0
	for i, delta := range mut.Deltas {
		root, count, err := w.commitDelta(ctx, namespace, delta)
		if err != nil {
			return WriteReceipt{}, fmt.Errorf("delta %d: %w", i, err)
		}
		newRoot = root
		arcCount += count
	}

	return WriteReceipt{
		BaseRoot:   mut.BaseRoot,
		NewRoot:    newRoot,
		DeltaCount: len(mut.Deltas),
		ArcCount:   arcCount,
	}, nil
}

func (w *Writer) commitDelta(ctx context.Context, namespace string, delta ArcSetDelta) (cid.Cid, int, error) {
	switch delta.Kind {
	case arcset.KindMap:
		if w.semantic == nil {
			return cid.Undef, 0, errors.New("map semantics is nil")
		}
		root, err := w.commitMapDelta(ctx, namespace, delta)
		if err != nil {
			return cid.Undef, 0, err
		}
		if err := checkExpectedRoot(delta.ExpectedRoot, root); err != nil {
			return cid.Undef, 0, err
		}
		return root, delta.Changes.Len(), nil
	case arcset.KindList:
		if w.listSemantic == nil {
			return cid.Undef, 0, errors.New("list semantics is nil")
		}
		root, err := w.commitListDelta(ctx, namespace, delta)
		if err != nil {
			return cid.Undef, 0, err
		}
		if err := checkExpectedRoot(delta.ExpectedRoot, root); err != nil {
			return cid.Undef, 0, err
		}
		return root, delta.Changes.Len(), nil
	default:
		return cid.Undef, 0, fmt.Errorf("%w: %q", arcset.ErrInvalidKind, delta.Kind)
	}
}

func (w *Writer) commitMapDelta(ctx context.Context, namespace string, delta ArcSetDelta) (cid.Cid, error) {
	changes := delta.Changes.Changes()
	if !delta.Object.Defined() {
		entries := make(map[arcset.Path]cid.Cid, len(changes))
		for _, change := range changes {
			if change.Before != nil {
				return cid.Undef, fmt.Errorf("create map delta has before value for %s", change.Coordinate.String())
			}
			if change.After == nil {
				return cid.Undef, fmt.Errorf("create map delta deletes %s", change.Coordinate.String())
			}
			key := arcset.CanonicalizePath(change.Coordinate.String())
			entries[key] = change.After.CID()
		}
		view := mapping.NewViewFromPaths(entries)
		root, err := w.semantic.Commit(ctx, namespace, view)
		if err != nil {
			return cid.Undef, err
		}
		if w.materializer != nil {
			snapshot, err := arcset.NewArcSetFromPaths(entries)
			if err != nil {
				return cid.Undef, err
			}
			retryBase, err := materializationRetryBase(ctx, w.materializer, namespace)
			if err != nil {
				return cid.Undef, &MaterializationWriteFailedError{
					NewRoot:              root,
					Namespace:            namespace,
					OldRoot:              cid.Undef,
					MaterializationDelta: snapshot,
					Cause:                fmt.Errorf("Materializer.Snapshot retry base failed: %w", err),
				}
			}
			if err := w.materializer.Update(ctx, namespace, root, cid.Undef, snapshot); err != nil {
				return cid.Undef, &MaterializationWriteFailedError{
					NewRoot:              root,
					Namespace:            namespace,
					OldRoot:              cid.Undef,
					MaterializationBase:  retryBase,
					MaterializationDelta: snapshot,
					Cause:                err,
				}
			}
		}
		return root, nil
	}

	updates := make([]mapping.BatchUpdate, 0, len(changes))
	logical := make(map[arcset.Path]cid.Cid, len(changes))
	for _, change := range changes {
		key := arcset.CanonicalizePath(change.Coordinate.String())
		oldValue := cid.Undef
		if change.Before != nil {
			oldValue = change.Before.CID()
		}
		newValue := cid.Undef
		if change.After != nil {
			newValue = change.After.CID()
		}
		updates = append(updates, mapping.BatchUpdate{
			Key:      key,
			OldValue: oldValue,
			NewValue: newValue,
		})
		logical[key] = newValue
	}
	root, err := w.semantic.BatchUpdate(ctx, namespace, delta.Object, updates)
	if err != nil {
		return cid.Undef, err
	}
	if w.materializer != nil {
		deltaSet, err := arcset.NewArcSetFromPaths(logical)
		if err != nil {
			return cid.Undef, err
		}
		retryBase, err := materializationRetryBase(ctx, w.materializer, namespace)
		if err != nil {
			return cid.Undef, &MaterializationWriteFailedError{
				NewRoot:              root,
				Namespace:            namespace,
				OldRoot:              delta.Object,
				MaterializationDelta: deltaSet,
				Cause:                fmt.Errorf("Materializer.Snapshot retry base failed: %w", err),
			}
		}
		if err := w.materializer.Update(ctx, namespace, root, delta.Object, deltaSet); err != nil {
			return cid.Undef, &MaterializationWriteFailedError{
				NewRoot:              root,
				Namespace:            namespace,
				OldRoot:              delta.Object,
				MaterializationBase:  retryBase,
				MaterializationDelta: deltaSet,
				Cause:                err,
			}
		}
	}
	return root, nil
}

func (w *Writer) commitListDelta(ctx context.Context, namespace string, delta ArcSetDelta) (cid.Cid, error) {
	changes := delta.Changes.Changes()
	if !delta.Object.Defined() {
		values, err := listCreateValues(changes)
		if err != nil {
			return cid.Undef, err
		}
		return w.commitList(ctx, namespace, values, delta.Commit)
	}

	length, err := w.listLength(ctx, namespace, delta.Object)
	if err != nil {
		return cid.Undef, err
	}
	root := delta.Object
	deleteFrom := length
	deleteSeen := map[uint64]struct{}{}

	for _, change := range changes {
		index, err := listChangeIndex(change)
		if err != nil {
			return cid.Undef, err
		}
		if change.Before != nil {
			query, proof, err := w.listSemantic.Prove(ctx, namespace, delta.Object, index)
			if err != nil {
				return cid.Undef, err
			}
			ok, err := w.listSemantic.Verify(delta.Object, index, query, proof)
			if err != nil {
				return cid.Undef, err
			}
			if !ok {
				return cid.Undef, fmt.Errorf("list proof failed at index %d", index)
			}
			if !query.Key.Equals(change.Before.CID()) {
				return cid.Undef, fmt.Errorf("old value mismatch at list index %d", index)
			}
		}
		if change.After == nil {
			if change.Before == nil {
				return cid.Undef, fmt.Errorf("list delete at %d is missing before value", index)
			}
			if index < deleteFrom {
				deleteFrom = index
			}
			deleteSeen[index] = struct{}{}
		}
	}
	if len(deleteSeen) > 0 {
		if deleteFrom >= length {
			return cid.Undef, fmt.Errorf("list delete starts beyond length")
		}
		for index := deleteFrom; index < length; index++ {
			if _, ok := deleteSeen[index]; !ok {
				return cid.Undef, fmt.Errorf("list delta deletes non-suffix index %d", index)
			}
		}
	}

	for _, change := range changes {
		if change.After == nil {
			continue
		}
		index, err := listChangeIndex(change)
		if err != nil {
			return cid.Undef, err
		}
		switch {
		case index < length:
			if change.Before == nil {
				return cid.Undef, fmt.Errorf("list replace at %d is missing before value", index)
			}
			root, err = w.listSemantic.Replace(ctx, namespace, root, index, change.Before.CID(), change.After.CID())
		case index == length:
			if delta.Commit.FixedList != nil {
				appender, ok := w.listSemantic.(list.FixedWidthAppender)
				if !ok {
					return cid.Undef, errors.New("list semantics does not support fixed list append")
				}
				var newIndex uint64
				totalSize := fixedAppendTotalSize(index+1, delta.Commit.FixedList.ChunkSize, delta.Commit.FixedList.TotalSize)
				root, newIndex, err = appender.AppendFixed(ctx, namespace, root, change.After.CID(), totalSize)
				if err == nil && newIndex != index {
					return cid.Undef, fmt.Errorf("fixed list append index = %d, want %d", newIndex, index)
				}
			} else {
				var newIndex uint64
				root, newIndex, err = w.listSemantic.Append(ctx, namespace, root, change.After.CID())
				if err == nil && newIndex != index {
					return cid.Undef, fmt.Errorf("list append index = %d, want %d", newIndex, index)
				}
			}
			length++
		default:
			return cid.Undef, fmt.Errorf("list delta is sparse at index %d", index)
		}
		if err != nil {
			return cid.Undef, err
		}
	}
	if len(deleteSeen) > 0 {
		if delta.Commit.FixedList != nil {
			return cid.Undef, errors.New("fixed list truncate is not supported")
		}
		var err error
		root, err = w.listSemantic.Truncate(ctx, namespace, root, deleteFrom)
		if err != nil {
			return cid.Undef, err
		}
	}
	return root, nil
}

func (w *Writer) commitList(ctx context.Context, namespace string, values []cid.Cid, descriptor CommitDescriptor) (cid.Cid, error) {
	if descriptor.FixedList == nil {
		return w.listSemantic.Commit(ctx, namespace, list.NewViewFromSlice(values))
	}
	measured, ok := w.listSemantic.(list.FixedWidthCommitter)
	if !ok {
		return cid.Undef, errors.New("list semantics does not support fixed list commits")
	}
	return measured.CommitFixed(ctx, namespace, values, descriptor.FixedList.ChunkSize, descriptor.FixedList.TotalSize)
}

func (w *Writer) listLength(ctx context.Context, namespace string, root cid.Cid) (uint64, error) {
	query, proof, err := w.listSemantic.Prove(ctx, namespace, root, 0)
	if err != nil {
		return 0, err
	}
	ok, err := w.listSemantic.Verify(root, 0, query, proof)
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, errors.New("list length proof failed")
	}
	return query.Length, nil
}

func listCreateValues(changes []arcset.ArcChange) ([]cid.Cid, error) {
	values := make([]cid.Cid, len(changes))
	for i, change := range changes {
		if change.Before != nil {
			return nil, fmt.Errorf("create list delta has before value at %s", change.Coordinate.String())
		}
		if change.After == nil {
			return nil, fmt.Errorf("create list delta deletes %s", change.Coordinate.String())
		}
		index, err := listChangeIndex(change)
		if err != nil {
			return nil, err
		}
		if index != uint64(i) {
			return nil, fmt.Errorf("create list delta is sparse at index %d", index)
		}
		values[i] = change.After.CID()
	}
	return values, nil
}

func listChangeIndex(change arcset.ArcChange) (uint64, error) {
	raw := change.Coordinate.Bytes()
	if len(raw) != 8 {
		return 0, fmt.Errorf("invalid canonical list coordinate %q", change.Coordinate.String())
	}
	return binary.BigEndian.Uint64(raw), nil
}

func fixedAppendTotalSize(childCount, chunkSize, finalTotalSize uint64) uint64 {
	total := childCount * chunkSize
	if total > finalTotalSize {
		return finalTotalSize
	}
	return total
}

func checkExpectedRoot(expectedRoot, actualRoot cid.Cid) error {
	if !expectedRoot.Defined() || expectedRoot.Equals(actualRoot) {
		return nil
	}
	return fmt.Errorf("%w: got %s want %s", ErrExpectedRootMismatch, actualRoot, expectedRoot)
}

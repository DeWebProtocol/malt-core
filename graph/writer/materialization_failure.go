package writer

import (
	"context"
	"errors"
	"fmt"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	cid "github.com/ipfs/go-cid"
)

// ErrMaterializationWriteFailed is returned when the semantic layer produced
// a new root but the ArcSet materialization write failed. The semantic
// commitment cannot be rolled back, so the error carries the exact retry.
var ErrMaterializationWriteFailed = errors.New("materializer materialization write failed after semantic commit")

// MaterializationWriteFailedError carries the root and exact materialization
// transition produced before a caller-owned materializer failed.
type MaterializationWriteFailedError struct {
	NewRoot              cid.Cid
	Namespace            string
	OldRoot              cid.Cid
	MaterializationBase  arcset.ArcSet
	MaterializationDelta arcset.ArcSet
	Cause                error
}

func (e *MaterializationWriteFailedError) Error() string {
	return fmt.Errorf("%w (newRoot=%s): %v", ErrMaterializationWriteFailed, e.NewRoot, e.Cause).Error()
}

func (e *MaterializationWriteFailedError) Unwrap() error {
	return errors.Join(ErrMaterializationWriteFailed, e.Cause)
}

// RetryMaterializationWrite retries the exact ArcSet transition captured by
// this error. Prefer Writer.RetryMaterializationWrite when a writer is
// available so legacy freshness guards serialize the retry.
func (e *MaterializationWriteFailedError) RetryMaterializationWrite(ctx context.Context, table Materializer) error {
	return e.retryMaterializationWrite(ctx, table)
}

func (e *MaterializationWriteFailedError) retryMaterializationWrite(ctx context.Context, table Materializer) error {
	if e == nil {
		return fmt.Errorf("materialization write failure is nil")
	}
	if table == nil {
		return fmt.Errorf("materializer is nil")
	}
	if e.MaterializationDelta == nil {
		return fmt.Errorf("%w: missing materialization delta", ErrMaterializationWriteFailed)
	}
	if !supportsConcurrentBranches(table) {
		if e.MaterializationBase == nil {
			return fmt.Errorf("%w: missing materialization retry base", ErrMaterializationWriteFailed)
		}
		current, err := table.Snapshot(ctx, e.Namespace, cid.Undef)
		if err != nil {
			return fmt.Errorf("Materializer.Snapshot failed during materialization retry: %w", err)
		}
		expectedAfter, err := applyArcSetDelta(e.MaterializationBase, e.MaterializationDelta)
		if err != nil {
			return err
		}
		matchesBase, err := arcSetsEqual(current, e.MaterializationBase)
		if err != nil {
			return err
		}
		matchesAfter, err := arcSetsEqual(current, expectedAfter)
		if err != nil {
			return err
		}
		if !matchesBase && !matchesAfter {
			return fmt.Errorf("%w: stale materialization retry for namespace %q oldRoot=%s newRoot=%s", ErrStaleRoot, e.Namespace, e.OldRoot, e.NewRoot)
		}
	}
	if err := table.Update(ctx, e.Namespace, e.NewRoot, e.OldRoot, e.MaterializationDelta); err != nil {
		return &MaterializationWriteFailedError{
			NewRoot:              e.NewRoot,
			Namespace:            e.Namespace,
			OldRoot:              e.OldRoot,
			MaterializationBase:  e.MaterializationBase,
			MaterializationDelta: e.MaterializationDelta,
			Cause:                err,
		}
	}
	return nil
}

func materializationRetryBase(ctx context.Context, table Materializer, namespace string) (arcset.ArcSet, error) {
	if table == nil || supportsConcurrentBranches(table) {
		return nil, nil
	}
	return table.Snapshot(ctx, namespace, cid.Undef)
}

func applyArcSetDelta(base, delta arcset.ArcSet) (arcset.ArcSet, error) {
	baseMap, err := arcset.ToPathMap(base)
	if err != nil {
		return nil, err
	}
	deltaMap, err := arcset.ToPathMap(delta)
	if err != nil {
		return nil, err
	}
	for path, target := range deltaMap {
		if target.Defined() {
			baseMap[path] = target
		} else {
			delete(baseMap, path)
		}
	}
	return arcset.NewArcSetFromPaths(baseMap)
}

func arcSetsEqual(a, b arcset.ArcSet) (bool, error) {
	aMap, err := arcset.ToPathMap(a)
	if err != nil {
		return false, err
	}
	bMap, err := arcset.ToPathMap(b)
	if err != nil {
		return false, err
	}
	if len(aMap) != len(bMap) {
		return false, nil
	}
	for path, aTarget := range aMap {
		bTarget, ok := bMap[path]
		if !ok || !aTarget.Equals(bTarget) {
			return false, nil
		}
	}
	return true, nil
}

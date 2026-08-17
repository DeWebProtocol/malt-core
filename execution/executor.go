// Package execution composes untrusted map/list provers and mutation appliers.
// It produces portable MALT results but never decides whether a client should
// trust them; callers verify results through package malt and auth/verifier.
package execution

import (
	"context"
	"errors"
	"fmt"
	"slices"

	malt "github.com/dewebprotocol/malt-core"
	"github.com/dewebprotocol/malt-core/auth/arcset"
	"github.com/dewebprotocol/malt-core/auth/proof/prooflist"
	structure "github.com/dewebprotocol/malt-core/auth/semantic"
	"github.com/dewebprotocol/malt-core/auth/semantic/list"
	"github.com/dewebprotocol/malt-core/auth/semantic/mapping"
	"github.com/dewebprotocol/malt-core/mutation"
	cid "github.com/ipfs/go-cid"
)

var ErrCapabilityUnavailable = errors.New("MALT executor capability is unavailable")

type MapReader interface {
	Prove(context.Context, string, cid.Cid, arcset.Path) (mapping.Binding, structure.Proof, error)
}

type ListReader interface {
	Prove(context.Context, string, cid.Cid, uint64) (list.Query, structure.Proof, error)
}

type MeasuredListReader interface {
	ListReader
	ProveRange(context.Context, string, cid.Cid, uint64, *uint64) (list.RangeResult, structure.Proof, error)
}

type MutationApplier interface {
	Apply(context.Context, string, mutation.SemanticMutation) (mutation.WriteReceipt, error)
}

type Options struct {
	Scope    string
	Resolver malt.Resolver
	Maps     MapReader
	Lists    ListReader
	Writer   MutationApplier
}

// Executor is an untrusted execution facade. Scope is backend placement state,
// not part of canonical queries or mutations.
type Executor struct {
	scope    string
	resolver malt.Resolver
	maps     MapReader
	lists    ListReader
	writer   MutationApplier
}

func NewExecutor(opts Options) (*Executor, error) {
	if opts.Scope == "" {
		return nil, fmt.Errorf("MALT executor scope is empty")
	}
	if opts.Resolver == nil && opts.Maps == nil && opts.Lists == nil && opts.Writer == nil {
		return nil, fmt.Errorf("MALT executor has no configured capabilities")
	}
	return &Executor{scope: opts.Scope, resolver: opts.Resolver, maps: opts.Maps, lists: opts.Lists, writer: opts.Writer}, nil
}

// Resolve executes one canonical segment-path derivation. The returned result
// is untrusted until the caller applies malt.VerifyResolve.
func (e *Executor) Resolve(ctx context.Context, req malt.ResolveRequest) (malt.ResolveResult, error) {
	if e == nil {
		return malt.ResolveResult{}, fmt.Errorf("MALT executor is nil")
	}
	if err := req.Validate(); err != nil {
		return malt.ResolveResult{}, err
	}
	path, _ := malt.NewSegmentPath(req.Segments)
	if path.Empty() {
		return malt.ResolveResult{
			Target:    req.Root,
			ProofList: prooflist.ProofList{Root: req.Root, Query: "", Steps: []prooflist.Step{}},
		}, nil
	}
	if e.resolver == nil {
		return malt.ResolveResult{}, fmt.Errorf("%w: path resolver", ErrCapabilityUnavailable)
	}
	return e.resolver.Resolve(ctx, req)
}

func (e *Executor) Read(ctx context.Context, req malt.ReadRequest) (malt.ReadResult, error) {
	if e == nil {
		return malt.ReadResult{}, fmt.Errorf("MALT executor is nil")
	}
	if !req.Root.Defined() {
		return malt.ReadResult{}, fmt.Errorf("root is undefined")
	}
	if err := req.Query.Validate(); err != nil {
		return malt.ReadResult{}, err
	}
	switch req.Query.Kind {
	case malt.QueryMapKey:
		return e.readMap(ctx, req)
	case malt.QueryListIndex:
		return e.readListIndex(ctx, req)
	case malt.QueryListRange:
		return e.readListRange(ctx, req)
	default:
		return malt.ReadResult{}, fmt.Errorf("%w: unsupported kind %q", malt.ErrInvalidQuery, req.Query.Kind)
	}
}

// ProveMap returns either a membership proof or an authenticated
// non-membership proof without changing Read's not-found behavior.
func (e *Executor) ProveMap(ctx context.Context, req malt.MapProofRequest) (malt.MapProofResult, error) {
	if e == nil {
		return malt.MapProofResult{}, fmt.Errorf("MALT executor is nil")
	}
	if err := req.Validate(); err != nil {
		return malt.MapProofResult{}, err
	}
	if e.maps == nil {
		return malt.MapProofResult{}, fmt.Errorf("%w: map reader", ErrCapabilityUnavailable)
	}
	binding, proof, err := e.maps.Prove(ctx, e.scope, req.Root, req.Key)
	if err != nil {
		return malt.MapProofResult{}, err
	}
	kind := prooflist.KindMapAbsence
	if binding.Present {
		if !binding.Value.Defined() {
			return malt.MapProofResult{}, fmt.Errorf("map proof returned a present binding with an undefined target")
		}
		kind = prooflist.KindMapStep
		if req.Key == arcset.PayloadPath {
			kind = prooflist.KindPayloadBinding
		}
	} else if binding.Value.Defined() {
		return malt.MapProofResult{}, fmt.Errorf("map proof returned an absent binding with a defined target")
	}
	step := prooflist.Step{
		Kind: kind, From: req.Root, Query: req.Key.String(), Coordinate: req.Key.String(), Path: req.Key.String(),
		Target: binding.Value, EvidenceKind: "structure", EvidenceBackend: "map", Proof: cloneProof(proof),
	}
	return malt.MapProofResult{
		Present: binding.Present, Target: binding.Value,
		ProofList: prooflist.ProofList{Root: req.Root, Query: req.Key.String(), Steps: []prooflist.Step{step}},
	}, nil
}

func (e *Executor) Apply(ctx context.Context, mut mutation.SemanticMutation) (mutation.WriteReceipt, error) {
	if e == nil {
		return mutation.WriteReceipt{}, fmt.Errorf("MALT executor is nil")
	}
	if e.writer == nil {
		return mutation.WriteReceipt{}, fmt.Errorf("%w: mutation applier", ErrCapabilityUnavailable)
	}
	return e.writer.Apply(ctx, e.scope, mut)
}

func (e *Executor) readMap(ctx context.Context, req malt.ReadRequest) (malt.ReadResult, error) {
	if e.maps == nil {
		return malt.ReadResult{}, fmt.Errorf("%w: map reader", ErrCapabilityUnavailable)
	}
	binding, proof, err := e.maps.Prove(ctx, e.scope, req.Root, req.Query.Key)
	if err != nil {
		if errors.Is(err, mapping.ErrPathNotFound) {
			return malt.ReadResult{}, fmt.Errorf("%w: %w", malt.ErrQueryNotFound, err)
		}
		return malt.ReadResult{}, err
	}
	if !binding.Present || !binding.Value.Defined() {
		return malt.ReadResult{}, malt.ErrQueryNotFound
	}
	kind := prooflist.KindMapStep
	if req.Query.Key == arcset.PayloadPath {
		kind = prooflist.KindPayloadBinding
	}
	step := prooflist.Step{Kind: kind, From: req.Root, Query: req.Query.String(), Coordinate: req.Query.Key.String(), Path: req.Query.Key.String(), Target: binding.Value, EvidenceKind: "structure", EvidenceBackend: "map", Proof: cloneProof(proof)}
	return resultFromStep(req, step, nil), nil
}

func (e *Executor) readListIndex(ctx context.Context, req malt.ReadRequest) (malt.ReadResult, error) {
	if e.lists == nil {
		return malt.ReadResult{}, fmt.Errorf("%w: list reader", ErrCapabilityUnavailable)
	}
	result, proof, err := e.lists.Prove(ctx, e.scope, req.Root, req.Query.Index)
	if err != nil {
		return malt.ReadResult{}, err
	}
	if !result.Key.Defined() {
		return malt.ReadResult{}, malt.ErrQueryNotFound
	}
	index, length := req.Query.Index, result.Length
	step := prooflist.Step{Kind: prooflist.KindListIndex, From: req.Root, Query: req.Query.String(), Coordinate: fmt.Sprintf("%d", index), Index: &index, Length: &length, Target: result.Key, EvidenceKind: "structure", EvidenceBackend: "list", Proof: cloneProof(proof)}
	return resultFromStep(req, step, nil), nil
}

func (e *Executor) readListRange(ctx context.Context, req malt.ReadRequest) (malt.ReadResult, error) {
	if e.lists == nil {
		return malt.ReadResult{}, fmt.Errorf("%w: list reader", ErrCapabilityUnavailable)
	}
	measured, ok := e.lists.(MeasuredListReader)
	if !ok {
		return malt.ReadResult{}, fmt.Errorf("%w: measured list reader", ErrCapabilityUnavailable)
	}
	result, proof, err := measured.ProveRange(ctx, e.scope, req.Root, req.Query.Start, req.Query.End)
	if err != nil {
		return malt.ReadResult{}, err
	}
	start, end := req.Query.Start, cloneUint64(req.Query.End)
	childCount, totalSize, chunkSize := result.Metadata.ChildCount, result.Metadata.TotalSize, result.Metadata.ChunkSize
	step := prooflist.Step{Kind: prooflist.KindListRange, From: req.Root, Query: req.Query.String(), Coordinate: req.Query.String(), Start: &start, End: end, ChildCount: &childCount, TotalSize: &totalSize, ChunkSize: &chunkSize, Target: req.Root, Segments: slices.Clone(result.Segments), EvidenceKind: "structure", EvidenceBackend: "measured_list", Proof: cloneProof(proof)}
	return resultFromStep(req, step, result.Segments), nil
}

func resultFromStep(req malt.ReadRequest, step prooflist.Step, segments []cid.Cid) malt.ReadResult {
	return malt.ReadResult{Target: step.Target, Segments: slices.Clone(segments), ProofList: prooflist.ProofList{Root: req.Root, Query: req.Query.String(), Steps: []prooflist.Step{step}}}
}

func cloneUint64(value *uint64) *uint64 {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneProof(proof structure.Proof) []byte { return slices.Clone([]byte(proof)) }

// Package protocol defines the versioned, transport-neutral serialized MALT
// resolve and read contracts. Semantic operations remain in package malt;
// ProofList is their evidence rather than a generic operation union.
package protocol

import (
	"fmt"

	malt "github.com/dewebprotocol/malt-core"
	"github.com/dewebprotocol/malt-core/auth/proof/prooflist"
	cid "github.com/ipfs/go-cid"
)

const (
	ResolveProfile = "malt.resolve/v0alpha1"
	ReadProfile    = "malt.read/v0alpha1"
)

// ResolveRequest is the serialized projection of malt.ResolveRequest.
type ResolveRequest struct {
	Profile  string   `json:"profile"`
	Root     string   `json:"root"`
	Segments []string `json:"segments"`
}

// ResolveResult carries the authenticated target and its ProofList evidence.
// Root and segments remain caller-selected inputs in ResolveRequest.
type ResolveResult struct {
	Profile   string              `json:"profile"`
	Target    string              `json:"target"`
	ProofList prooflist.ProofList `json:"prooflist"`
}

// ResolveVerification binds an independently constructed request to one
// untrusted result for local verification.
type ResolveVerification struct {
	Request ResolveRequest `json:"request"`
	Result  ResolveResult  `json:"result"`
}

type QueryKind string

const (
	QueryMapKey    QueryKind = "map_key"
	QueryListIndex QueryKind = "list_index"
	QueryListRange QueryKind = "list_range"
)

// Query is the serialized projection of one primitive malt.Query.
type Query struct {
	Kind     QueryKind `json:"kind"`
	Segments []string  `json:"segments,omitempty"`
	Index    *uint64   `json:"index,omitempty"`
	Start    *uint64   `json:"start,omitempty"`
	End      *uint64   `json:"end,omitempty"`
}

// ReadRequest is the serialized projection of malt.ReadRequest.
type ReadRequest struct {
	Profile string `json:"profile"`
	Root    string `json:"root"`
	Query   Query  `json:"query"`
}

// ReadResult carries one primitive read target, optional measured-range
// segment CIDs, and ProofList evidence.
type ReadResult struct {
	Profile       string              `json:"profile"`
	Target        string              `json:"target"`
	RangeSegments []string            `json:"range_segments,omitempty"`
	ProofList     prooflist.ProofList `json:"prooflist"`
}

// ReadVerification binds caller-selected primitive read inputs to one
// untrusted result for local verification.
type ReadVerification struct {
	Request ReadRequest `json:"request"`
	Result  ReadResult  `json:"result"`
}

// VerificationResult is returned by local WASM and diagnostic HTTP adapters.
type VerificationResult struct {
	Profile string `json:"profile"`
	Valid   bool   `json:"valid"`
	Error   string `json:"error,omitempty"`
}

// NewResolveRequest serializes one caller-selected core resolve request.
func NewResolveRequest(request malt.ResolveRequest) (ResolveRequest, error) {
	if err := request.Validate(); err != nil {
		return ResolveRequest{}, err
	}
	return ResolveRequest{
		Profile:  ResolveProfile,
		Root:     request.Root.String(),
		Segments: append([]string{}, request.Segments...),
	}, nil
}

func (r ResolveRequest) Validate() error {
	if r.Profile != ResolveProfile {
		return fmt.Errorf("unsupported resolve profile %q", r.Profile)
	}
	root, err := cid.Parse(r.Root)
	if err != nil {
		return fmt.Errorf("invalid resolve root CID: %w", err)
	}
	if r.Segments == nil {
		return fmt.Errorf("resolve segments field is required")
	}
	return (malt.ResolveRequest{Root: root, Segments: r.Segments}).Validate()
}

func (r ResolveRequest) Core() (malt.ResolveRequest, error) {
	if err := r.Validate(); err != nil {
		return malt.ResolveRequest{}, err
	}
	root, _ := cid.Parse(r.Root)
	return malt.ResolveRequest{Root: root, Segments: append([]string(nil), r.Segments...)}, nil
}

func NewResolveResult(result malt.ResolveResult) (ResolveResult, error) {
	if !result.Target.Defined() {
		return ResolveResult{}, fmt.Errorf("resolve target is undefined")
	}
	if !result.ProofList.Root.Defined() {
		return ResolveResult{}, fmt.Errorf("resolve ProofList root is undefined")
	}
	return ResolveResult{Profile: ResolveProfile, Target: result.Target.String(), ProofList: result.ProofList}, nil
}

func (r ResolveResult) Validate() error {
	if r.Profile != ResolveProfile {
		return fmt.Errorf("unsupported resolve result profile %q", r.Profile)
	}
	if _, err := cid.Parse(r.Target); err != nil {
		return fmt.Errorf("invalid resolve target CID: %w", err)
	}
	if !r.ProofList.Root.Defined() {
		return fmt.Errorf("resolve ProofList root is undefined")
	}
	return nil
}

func (r ResolveResult) Core() (malt.ResolveResult, error) {
	if err := r.Validate(); err != nil {
		return malt.ResolveResult{}, err
	}
	target, _ := cid.Parse(r.Target)
	return malt.ResolveResult{Target: target, ProofList: r.ProofList}, nil
}

func (v ResolveVerification) Validate() error {
	if err := v.Request.Validate(); err != nil {
		return err
	}
	return v.Result.Validate()
}

func (r ReadRequest) Validate() error {
	if r.Profile != ReadProfile {
		return fmt.Errorf("unsupported read profile %q", r.Profile)
	}
	if _, err := cid.Parse(r.Root); err != nil {
		return fmt.Errorf("invalid read root CID: %w", err)
	}
	return r.Query.Validate()
}

// NewReadRequest serializes one caller-selected core primitive read request.
func NewReadRequest(request malt.ReadRequest) (ReadRequest, error) {
	if !request.Root.Defined() {
		return ReadRequest{}, fmt.Errorf("read root is undefined")
	}
	query, err := QueryFromCore(request.Query)
	if err != nil {
		return ReadRequest{}, err
	}
	return ReadRequest{Profile: ReadProfile, Root: request.Root.String(), Query: query}, nil
}

func (r ReadRequest) Core() (malt.ReadRequest, error) {
	if err := r.Validate(); err != nil {
		return malt.ReadRequest{}, err
	}
	root, _ := cid.Parse(r.Root)
	query, _ := r.Query.Core()
	return malt.ReadRequest{Root: root, Query: query}, nil
}

func (q Query) Validate() error {
	_, err := q.Core()
	return err
}

func (q Query) Core() (malt.Query, error) {
	switch q.Kind {
	case QueryMapKey:
		if len(q.Segments) == 0 || q.Index != nil || q.Start != nil || q.End != nil {
			return malt.Query{}, fmt.Errorf("invalid map_key query fields")
		}
		path, err := malt.NewSegmentPath(q.Segments)
		if err != nil {
			return malt.Query{}, err
		}
		return malt.MapKeyQuery(path.String())
	case QueryListIndex:
		if q.Index == nil || len(q.Segments) != 0 || q.Start != nil || q.End != nil {
			return malt.Query{}, fmt.Errorf("invalid list_index query fields")
		}
		return malt.ListIndexQuery(*q.Index), nil
	case QueryListRange:
		if q.Start == nil || len(q.Segments) != 0 || q.Index != nil {
			return malt.Query{}, fmt.Errorf("invalid list_range query fields")
		}
		return malt.ListRangeQuery(*q.Start, q.End)
	default:
		return malt.Query{}, fmt.Errorf("unsupported read query kind %q", q.Kind)
	}
}

func QueryFromCore(query malt.Query) (Query, error) {
	if err := query.Validate(); err != nil {
		return Query{}, err
	}
	switch query.Kind {
	case malt.QueryMapKey:
		path, err := malt.ParseSegmentPath(query.Key.String())
		if err != nil {
			return Query{}, err
		}
		return Query{Kind: QueryMapKey, Segments: path.Segments()}, nil
	case malt.QueryListIndex:
		index := query.Index
		return Query{Kind: QueryListIndex, Index: &index}, nil
	case malt.QueryListRange:
		start := query.Start
		return Query{Kind: QueryListRange, Start: &start, End: cloneUint64(query.End)}, nil
	default:
		return Query{}, fmt.Errorf("unsupported read query kind %q", query.Kind)
	}
}

func NewReadResult(result malt.ReadResult) (ReadResult, error) {
	if !result.Target.Defined() {
		return ReadResult{}, fmt.Errorf("read target is undefined")
	}
	if !result.ProofList.Root.Defined() {
		return ReadResult{}, fmt.Errorf("read ProofList root is undefined")
	}
	segments := make([]string, len(result.Segments))
	for i, segment := range result.Segments {
		if !segment.Defined() {
			return ReadResult{}, fmt.Errorf("read range segment %d is undefined", i)
		}
		segments[i] = segment.String()
	}
	return ReadResult{Profile: ReadProfile, Target: result.Target.String(), RangeSegments: segments, ProofList: result.ProofList}, nil
}

func (r ReadResult) Validate() error {
	if r.Profile != ReadProfile {
		return fmt.Errorf("unsupported read result profile %q", r.Profile)
	}
	if _, err := cid.Parse(r.Target); err != nil {
		return fmt.Errorf("invalid read target CID: %w", err)
	}
	for i, segment := range r.RangeSegments {
		if _, err := cid.Parse(segment); err != nil {
			return fmt.Errorf("invalid read range segment %d: %w", i, err)
		}
	}
	if !r.ProofList.Root.Defined() {
		return fmt.Errorf("read ProofList root is undefined")
	}
	return nil
}

func (r ReadResult) Core() (malt.ReadResult, error) {
	if err := r.Validate(); err != nil {
		return malt.ReadResult{}, err
	}
	target, _ := cid.Parse(r.Target)
	segments := make([]cid.Cid, len(r.RangeSegments))
	for i, raw := range r.RangeSegments {
		segments[i], _ = cid.Parse(raw)
	}
	return malt.ReadResult{Target: target, Segments: segments, ProofList: r.ProofList}, nil
}

func (v ReadVerification) Validate() error {
	if err := v.Request.Validate(); err != nil {
		return err
	}
	return v.Result.Validate()
}

func cloneUint64(value *uint64) *uint64 {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

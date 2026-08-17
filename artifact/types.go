// Package artifact implements the frozen malt.artifact/v0alpha2 compatibility
// profile published by MALT v0.0.4. New integrations use package protocol's
// operation-specific resolve and read contracts.
package artifact

import (
	"bytes"
	"encoding/json"
	"fmt"

	malt "github.com/dewebprotocol/malt-core"
	"github.com/dewebprotocol/malt-core/auth/proof/prooflist"
	cid "github.com/ipfs/go-cid"
)

// Profile identifies the frozen artifact contract introduced by MALT v0.0.4.
// Its operation set is resolve and prove; incompatible extensions require a
// different serialized profile.
const Profile = "malt.artifact/v0alpha2"

type Operation string

const (
	OperationResolve Operation = "resolve"
	OperationProve   Operation = "prove"
)

type QueryKind string

const (
	QueryPath      QueryKind = "path"
	QueryMapKey    QueryKind = "map_key"
	QueryListIndex QueryKind = "list_index"
	QueryListRange QueryKind = "list_range"
)

// Query is the stable artifact projection of a MALT path or primitive typed
// query. Exactly the fields selected by Kind are meaningful.
type Query struct {
	Kind     QueryKind `json:"kind"`
	Segments []string  `json:"segments,omitempty"`
	Index    *uint64   `json:"index,omitempty"`
	Start    *uint64   `json:"start,omitempty"`
	End      *uint64   `json:"end,omitempty"`
}

// Equal reports whether two canonical artifact queries select the same
// operation input. Callers should validate both queries before relying on the
// result so irrelevant fields cannot be smuggled through an envelope.
func (q Query) Equal(other Query) bool {
	return q.Kind == other.Kind &&
		stringSlicesEqual(q.Segments, other.Segments) &&
		uint64PointersEqual(q.Index, other.Index) &&
		uint64PointersEqual(q.Start, other.Start) &&
		uint64PointersEqual(q.End, other.End)
}

// MarshalJSON emits exactly the fields allowed by the selected query kind.
// Path queries always carry segments, including the zero-segment identity
// query required by the published schema.
func (q Query) MarshalJSON() ([]byte, error) {
	if err := q.Validate(q.Kind == QueryPath); err != nil {
		return nil, err
	}
	switch q.Kind {
	case QueryPath, QueryMapKey:
		segments := q.Segments
		if segments == nil {
			segments = []string{}
		}
		return json.Marshal(struct {
			Kind     QueryKind `json:"kind"`
			Segments []string  `json:"segments"`
		}{Kind: q.Kind, Segments: segments})
	case QueryListIndex:
		return json.Marshal(struct {
			Kind  QueryKind `json:"kind"`
			Index uint64    `json:"index"`
		}{Kind: q.Kind, Index: *q.Index})
	case QueryListRange:
		return json.Marshal(struct {
			Kind  QueryKind `json:"kind"`
			Start uint64    `json:"start"`
			End   *uint64   `json:"end,omitempty"`
		}{Kind: q.Kind, Start: *q.Start, End: q.End})
	default:
		return nil, fmt.Errorf("unsupported artifact query kind %q", q.Kind)
	}
}

// UnmarshalJSON enforces the same conditional field set as the published JSON
// Schema instead of silently ignoring unrelated or unknown query fields.
func (q *Query) UnmarshalJSON(data []byte) error {
	if q == nil {
		return fmt.Errorf("artifact query receiver is nil")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("decode artifact query: %w", err)
	}
	kindField, ok := fields["kind"]
	if !ok {
		return fmt.Errorf("artifact query has no kind")
	}
	var kind QueryKind
	if err := json.Unmarshal(kindField, &kind); err != nil {
		return fmt.Errorf("decode artifact query kind: %w", err)
	}

	decoded := Query{Kind: kind}
	switch kind {
	case QueryPath:
		if err := requireOnlyQueryFields(fields, "kind", "segments"); err != nil {
			return err
		}
		segments, ok := fields["segments"]
		if !ok {
			// v0.0.4 encoded the zero-segment identity query without a
			// segments field because the slice used omitempty. Keep the same
			// artifact profile compatible and normalize it to the canonical
			// empty segment array.
			decoded.Segments = []string{}
			break
		}
		if bytes.Equal(bytes.TrimSpace(segments), []byte("null")) {
			return fmt.Errorf("path query segments are null")
		}
		if err := json.Unmarshal(segments, &decoded.Segments); err != nil {
			return fmt.Errorf("decode path query segments: %w", err)
		}
	case QueryMapKey:
		if err := requireOnlyQueryFields(fields, "kind", "segments"); err != nil {
			return err
		}
		segments, ok := fields["segments"]
		if !ok || bytes.Equal(bytes.TrimSpace(segments), []byte("null")) {
			return fmt.Errorf("map_key query has no segments")
		}
		if err := json.Unmarshal(segments, &decoded.Segments); err != nil {
			return fmt.Errorf("decode map_key query segments: %w", err)
		}
	case QueryListIndex:
		if err := requireOnlyQueryFields(fields, "kind", "index"); err != nil {
			return err
		}
		index, ok := fields["index"]
		if !ok || bytes.Equal(bytes.TrimSpace(index), []byte("null")) {
			return fmt.Errorf("list_index query has no index")
		}
		var value uint64
		if err := json.Unmarshal(index, &value); err != nil {
			return fmt.Errorf("decode list_index query index: %w", err)
		}
		decoded.Index = &value
	case QueryListRange:
		if err := requireOnlyQueryFields(fields, "kind", "start", "end"); err != nil {
			return err
		}
		start, ok := fields["start"]
		if !ok || bytes.Equal(bytes.TrimSpace(start), []byte("null")) {
			return fmt.Errorf("list_range query has no start")
		}
		var value uint64
		if err := json.Unmarshal(start, &value); err != nil {
			return fmt.Errorf("decode list_range query start: %w", err)
		}
		decoded.Start = &value
		if end, ok := fields["end"]; ok {
			if bytes.Equal(bytes.TrimSpace(end), []byte("null")) {
				return fmt.Errorf("list_range query end is null")
			}
			var endValue uint64
			if err := json.Unmarshal(end, &endValue); err != nil {
				return fmt.Errorf("decode list_range query end: %w", err)
			}
			decoded.End = &endValue
		}
	default:
		return fmt.Errorf("unsupported artifact query kind %q", kind)
	}
	if err := decoded.Validate(kind == QueryPath); err != nil {
		return err
	}
	*q = decoded
	return nil
}

// ResolveRequest asks an execution engine for one authenticated derivation of
// a caller-supplied segment path. Candidate selection is not part of the proof
// contract; the reference engine currently prefers the longest prefix.
type ResolveRequest struct {
	Profile  string   `json:"profile"`
	Root     string   `json:"root"`
	Segments []string `json:"segments"`
}

// ProveRequest asks for one primitive typed map/list proof.
type ProveRequest struct {
	Profile string `json:"profile"`
	Root    string `json:"root"`
	Query   Query  `json:"query"`
}

// Artifact binds one request, target, and ProofList under an explicit profile.
// RangeSegments is populated only for measured-list range proofs.
type Artifact struct {
	Profile       string              `json:"profile"`
	Operation     Operation           `json:"operation"`
	Root          string              `json:"root"`
	Query         Query               `json:"query"`
	Target        string              `json:"target"`
	RangeSegments []string            `json:"range_segments,omitempty"`
	ProofList     prooflist.ProofList `json:"prooflist"`
}

// VerifyRequest asks a verifier to validate all artifact bindings and proof
// evidence without trusting the resolver or gateway that produced it.
type VerifyRequest struct {
	Profile  string   `json:"profile"`
	Artifact Artifact `json:"artifact"`
}

type VerifyResult struct {
	Profile string `json:"profile"`
	Valid   bool   `json:"valid"`
}

func (r ResolveRequest) Validate() error {
	if r.Profile != Profile {
		return fmt.Errorf("unsupported artifact profile %q", r.Profile)
	}
	if _, err := cid.Parse(r.Root); err != nil {
		return fmt.Errorf("invalid root CID: %w", err)
	}
	if _, err := malt.NewSegmentPath(r.Segments); err != nil {
		return err
	}
	return nil
}

func (r ProveRequest) Validate() error {
	if r.Profile != Profile {
		return fmt.Errorf("unsupported artifact profile %q", r.Profile)
	}
	if _, err := cid.Parse(r.Root); err != nil {
		return fmt.Errorf("invalid root CID: %w", err)
	}
	return r.Query.Validate(false)
}

func (r VerifyRequest) Validate() error {
	if r.Profile != Profile {
		return fmt.Errorf("unsupported verify profile %q", r.Profile)
	}
	return r.Artifact.Validate()
}

func (q Query) Validate(allowPath bool) error {
	switch q.Kind {
	case QueryPath:
		if !allowPath {
			return fmt.Errorf("path query is only valid for resolve artifacts")
		}
		if q.Index != nil || q.Start != nil || q.End != nil {
			return fmt.Errorf("path query contains list fields")
		}
		_, err := malt.NewSegmentPath(q.Segments)
		return err
	case QueryMapKey:
		path, err := malt.NewSegmentPath(q.Segments)
		if err != nil {
			return err
		}
		if path.Empty() {
			return fmt.Errorf("map_key query has no segments")
		}
		if q.Index != nil || q.Start != nil || q.End != nil {
			return fmt.Errorf("map_key query contains list fields")
		}
		return nil
	case QueryListIndex:
		if q.Index == nil {
			return fmt.Errorf("list_index query has no index")
		}
		if len(q.Segments) != 0 || q.Start != nil || q.End != nil {
			return fmt.Errorf("list_index query contains unrelated fields")
		}
		return nil
	case QueryListRange:
		if q.Start == nil {
			return fmt.Errorf("list_range query has no start")
		}
		if q.End != nil && *q.End <= *q.Start {
			return fmt.Errorf("list_range end must be greater than start")
		}
		if len(q.Segments) != 0 || q.Index != nil {
			return fmt.Errorf("list_range query contains unrelated fields")
		}
		return nil
	default:
		return fmt.Errorf("unsupported artifact query kind %q", q.Kind)
	}
}

func (q Query) Core() (malt.Query, error) {
	if err := q.Validate(false); err != nil {
		return malt.Query{}, err
	}
	switch q.Kind {
	case QueryMapKey:
		path, _ := malt.NewSegmentPath(q.Segments)
		return malt.MapKeyQuery(path.String())
	case QueryListIndex:
		return malt.ListIndexQuery(*q.Index), nil
	case QueryListRange:
		return malt.ListRangeQuery(*q.Start, q.End)
	default:
		return malt.Query{}, fmt.Errorf("unsupported artifact query kind %q", q.Kind)
	}
}

func QueryFromCore(query malt.Query) (Query, error) {
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
		return Query{}, fmt.Errorf("unsupported core query kind %q", query.Kind)
	}
}

func NewResolveArtifact(req ResolveRequest, target cid.Cid, pl prooflist.ProofList) (Artifact, error) {
	if err := req.Validate(); err != nil {
		return Artifact{}, err
	}
	if !target.Defined() {
		return Artifact{}, fmt.Errorf("resolved target is undefined")
	}
	return Artifact{
		Profile:   Profile,
		Operation: OperationResolve,
		Root:      req.Root,
		Query:     Query{Kind: QueryPath, Segments: append([]string(nil), req.Segments...)},
		Target:    target.String(),
		ProofList: pl,
	}, nil
}

func NewProveArtifact(req ProveRequest, result malt.ReadResult) (Artifact, error) {
	if err := req.Validate(); err != nil {
		return Artifact{}, err
	}
	if !result.Target.Defined() {
		return Artifact{}, fmt.Errorf("proved target is undefined")
	}
	segments := make([]string, len(result.Segments))
	for i, segment := range result.Segments {
		segments[i] = segment.String()
	}
	return Artifact{
		Profile:       Profile,
		Operation:     OperationProve,
		Root:          req.Root,
		Query:         req.Query,
		Target:        result.Target.String(),
		RangeSegments: segments,
		ProofList:     result.ProofList,
	}, nil
}

func (a Artifact) Validate() error {
	if a.Profile != Profile {
		return fmt.Errorf("unsupported artifact profile %q", a.Profile)
	}
	if _, err := cid.Parse(a.Root); err != nil {
		return fmt.Errorf("invalid artifact root CID: %w", err)
	}
	if _, err := cid.Parse(a.Target); err != nil {
		return fmt.Errorf("invalid artifact target CID: %w", err)
	}
	switch a.Operation {
	case OperationResolve:
		if err := a.Query.Validate(true); err != nil {
			return err
		}
		if a.Query.Kind != QueryPath {
			return fmt.Errorf("resolve artifact must use a path query")
		}
		if len(a.RangeSegments) != 0 {
			return fmt.Errorf("resolve artifact contains range segments")
		}
	case OperationProve:
		if err := a.Query.Validate(false); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported artifact operation %q", a.Operation)
	}
	for i, segment := range a.RangeSegments {
		if _, err := cid.Parse(segment); err != nil {
			return fmt.Errorf("invalid range segment %d: %w", i, err)
		}
	}
	return nil
}

func cloneUint64(value *uint64) *uint64 {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func stringSlicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func uint64PointersEqual(left, right *uint64) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func requireOnlyQueryFields(fields map[string]json.RawMessage, allowed ...string) error {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, field := range allowed {
		allowedSet[field] = struct{}{}
	}
	for field := range fields {
		if _, ok := allowedSet[field]; !ok {
			return fmt.Errorf("%s query contains unrelated field %q", fieldsQueryKind(fields), field)
		}
	}
	return nil
}

func fieldsQueryKind(fields map[string]json.RawMessage) QueryKind {
	var kind QueryKind
	_ = json.Unmarshal(fields["kind"], &kind)
	return kind
}

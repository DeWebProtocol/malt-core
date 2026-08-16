// Package malt exposes the application-neutral MALT core facade.
//
// The facade is intentionally small. Client/application adapters translate
// domain operations into typed map/list queries and semantic mutations, while
// runtime state placement, ArcTable namespaces, HTTP transport, and payload CAS
// access remain outside the caller-visible contract.
package malt

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	"github.com/dewebprotocol/malt-core/auth/proof/prooflist"
	"github.com/dewebprotocol/malt-core/mutation"
	cid "github.com/ipfs/go-cid"
)

// QueryKind identifies one application-neutral semantic query.
type QueryKind string

const (
	// QueryMapKey authenticates one keyed map relation.
	QueryMapKey QueryKind = "map_key"
	// QueryListIndex authenticates one stable list index.
	QueryListIndex QueryKind = "list_index"
	// QueryListRange authenticates one measured-list byte range.
	QueryListRange QueryKind = "list_range"
)

var (
	// ErrInvalidQuery is returned when a typed query is incomplete or malformed.
	ErrInvalidQuery = errors.New("invalid MALT query")
	// ErrQueryNotFound is returned when a query has no authenticated target.
	ErrQueryNotFound = errors.New("MALT query target not found")
	// ErrVerifierRejected is returned when proof verification returns false.
	ErrVerifierRejected = errors.New("MALT verifier rejected read result")
)

// Query is a single typed arc query. Multi-step application traversal is
// composed by clients/application adapters from these primitive operations.
type Query struct {
	Kind  QueryKind
	Key   arcset.Path
	Index uint64
	Start uint64
	End   *uint64
}

// MapKeyQuery creates an exact keyed-map query.
func MapKeyQuery(rawKey string) (Query, error) {
	key, err := arcset.NewPath(rawKey)
	if err != nil {
		return Query{}, fmt.Errorf("%w: %v", ErrInvalidQuery, err)
	}
	return Query{Kind: QueryMapKey, Key: key}, nil
}

// ListIndexQuery creates a stable-indexed list query.
func ListIndexQuery(index uint64) Query {
	return Query{Kind: QueryListIndex, Index: index}
}

// ListRangeQuery creates a measured-list range query over [start, end). A nil
// end means the authenticated total size.
func ListRangeQuery(start uint64, end *uint64) (Query, error) {
	if end != nil && *end <= start {
		return Query{}, fmt.Errorf("%w: range end must be greater than start", ErrInvalidQuery)
	}
	return Query{Kind: QueryListRange, Start: start, End: cloneUint64(end)}, nil
}

// Validate checks the typed query contract.
func (q Query) Validate() error {
	switch q.Kind {
	case QueryMapKey:
		if q.Key.IsEmpty() {
			return fmt.Errorf("%w: map key is empty", ErrInvalidQuery)
		}
	case QueryListIndex:
		return nil
	case QueryListRange:
		if q.End != nil && *q.End <= q.Start {
			return fmt.Errorf("%w: range end must be greater than start", ErrInvalidQuery)
		}
	default:
		return fmt.Errorf("%w: unsupported kind %q", ErrInvalidQuery, q.Kind)
	}
	return nil
}

// String returns the current v0alpha1 query label used in ProofList evidence.
func (q Query) String() string {
	switch q.Kind {
	case QueryMapKey:
		return q.Key.String()
	case QueryListIndex:
		return "list:" + strconv.FormatUint(q.Index, 10)
	case QueryListRange:
		end := ""
		if q.End != nil {
			end = strconv.FormatUint(*q.End, 10)
		}
		return "range:" + strconv.FormatUint(q.Start, 10) + ":" + end
	default:
		return ""
	}
}

// ReadRequest binds a typed query to a caller-supplied trusted root.
type ReadRequest struct {
	Root  cid.Cid
	Query Query
}

// ReadResult is the verifier-facing result of one typed query. Target is the
// authenticated relation target. Segments is populated only for measured-list
// ranges and remains ordered as authenticated by ProofList.
type ReadResult struct {
	Target    cid.Cid
	Segments  []cid.Cid
	ProofList prooflist.ProofList
}

// MapProofRequest binds one keyed-map membership or non-membership proof to a
// caller-supplied trusted root.
type MapProofRequest struct {
	Root cid.Cid
	Key  arcset.Path
}

// Validate checks the transport-neutral map-proof request.
func (r MapProofRequest) Validate() error {
	if !r.Root.Defined() {
		return fmt.Errorf("trusted root is undefined")
	}
	key, err := arcset.NewPath(r.Key.String())
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidQuery, err)
	}
	if key != r.Key {
		return fmt.Errorf("%w: map key %q is not canonical", ErrInvalidQuery, r.Key)
	}
	return nil
}

// MapProofResult carries either a present target or an authenticated absence.
// Target is defined if and only if Present is true.
type MapProofResult struct {
	Present   bool
	Target    cid.Cid
	ProofList prooflist.ProofList
}

// ResolveRequest binds one canonical segment path to a caller-supplied trusted
// root. Applications append reserved coordinates such as @payload explicitly;
// an empty segment sequence always denotes root identity.
type ResolveRequest struct {
	Root     cid.Cid
	Segments []string
}

// Validate checks the transport-neutral resolution request.
func (r ResolveRequest) Validate() error {
	if !r.Root.Defined() {
		return fmt.Errorf("trusted root is undefined")
	}
	_, err := NewSegmentPath(r.Segments)
	return err
}

// ResolveResult is the authenticated target plus the ordered evidence for one
// complete segment-path derivation.
type ResolveResult struct {
	Target    cid.Cid
	ProofList prooflist.ProofList
}

// Mutation is the portable semantic mutation contract. Runtime state placement
// and publication policy are deliberately absent.
type Mutation = mutation.SemanticMutation

// WriteResult is the current v0alpha1 result-root receipt.
type WriteResult = mutation.WriteReceipt

// Reader is the application-neutral root-relative read port.
type Reader interface {
	Read(context.Context, ReadRequest) (ReadResult, error)
}

// MapProver is the application-neutral membership/non-membership proof port.
type MapProver interface {
	ProveMap(context.Context, MapProofRequest) (MapProofResult, error)
}

// Resolver is the application-neutral path-resolution port. Implementations
// execute against untrusted runtime state; clients call VerifyResolve before
// accepting the returned target.
type Resolver interface {
	Resolve(context.Context, ResolveRequest) (ResolveResult, error)
}

func cloneUint64(value *uint64) *uint64 {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

// Package verifier verifies ProofList evidence without graph runtime, ArcTable,
// storage, layout, server, or daemon dependencies.
package verifier

import (
	"context"
	"fmt"
	"strings"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	"github.com/dewebprotocol/malt-core/auth/proof/prooflist"
	structure "github.com/dewebprotocol/malt-core/auth/semantic"
	"github.com/dewebprotocol/malt-core/auth/semantic/list"
	"github.com/dewebprotocol/malt-core/auth/semantic/mapping"
	cid "github.com/ipfs/go-cid"
)

// MapVerifier is the minimum keyed-map surface required to verify a ProofList.
// Stateful map semantics satisfy this interface, but portable clients can use a
// verification-only implementation backed solely by a commitment scheme.
type MapVerifier interface {
	Verify(root cid.Cid, key arcset.Path, expected mapping.Binding, proof structure.Proof) (bool, error)
}

// ListVerifier is the minimum stable-list surface required to verify a
// list_index ProofList step.
type ListVerifier interface {
	Verify(root cid.Cid, index uint64, expected list.Query, proof structure.Proof) (bool, error)
}

// MeasuredListVerifier extends ListVerifier with byte-range verification.
type MeasuredListVerifier interface {
	ListVerifier
	VerifyRange(root cid.Cid, start uint64, end *uint64, expected list.RangeResult, proof structure.Proof) (bool, error)
}

type verifierProvider interface {
	mapVerifier(cid.Cid) (MapVerifier, error)
	listVerifier(cid.Cid) (ListVerifier, error)
}

type staticProvider struct {
	maps  MapVerifier
	lists ListVerifier
}

func (p staticProvider) mapVerifier(cid.Cid) (MapVerifier, error) {
	if p.maps == nil {
		return nil, fmt.Errorf("map verifier is nil")
	}
	return p.maps, nil
}

func (p staticProvider) listVerifier(cid.Cid) (ListVerifier, error) {
	if p.lists == nil {
		return nil, fmt.Errorf("list verifier is nil")
	}
	return p.lists, nil
}

// Verifier verifies ordered ProofList structure, query binding, and all
// cryptographic map/list evidence through verification-only backends.
type Verifier struct {
	provider verifierProvider
}

// New creates a verifier over fixed map and list verification surfaces. This
// constructor is used by runtime adapters and test doubles.
func New(maps MapVerifier, lists ListVerifier) *Verifier {
	return &Verifier{provider: staticProvider{maps: maps, lists: lists}}
}

// NewWithRegistry creates a verifier that selects commitment backends from the
// typed CID at each proof step. It is the portable client constructor.
func NewWithRegistry(registry *BackendRegistry) *Verifier {
	return &Verifier{provider: registry}
}

// NewDefault creates a portable verifier supporting the built-in KZG and IPA
// commitment backends.
func NewDefault() (*Verifier, error) {
	registry, err := NewDefaultBackendRegistry()
	if err != nil {
		return nil, err
	}
	return NewWithRegistry(registry), nil
}

type proofListVerifiedPath struct {
	parts             []string
	hasPayloadBinding bool
}

func (p *proofListVerifiedPath) addStep(step prooflist.Step) error {
	if step.Kind == prooflist.KindListIndex || step.Kind == prooflist.KindListRange {
		return nil
	}

	path := arcset.CanonicalizePath(step.Path).String()
	if path == "" {
		return nil
	}
	if p.hasPayloadBinding {
		return fmt.Errorf("prooflist traversal step %q appears after terminal @payload binding", path)
	}
	if step.Kind == prooflist.KindPayloadBinding {
		if path != arcset.PayloadPath.String() {
			return fmt.Errorf("prooflist payload_binding step uses path %q, want @payload", path)
		}
		p.hasPayloadBinding = true
		return nil
	}
	if path == arcset.PayloadPath.String() {
		return fmt.Errorf("prooflist @payload path must use payload_binding kind")
	}
	p.parts = append(p.parts, path)
	return nil
}

func (p proofListVerifiedPath) logicalQueryPath() string {
	return strings.Join(p.parts, "/")
}

// VerifyProofList verifies a complete ordered ProofList. The context is
// accepted for facade compatibility; primitive verification is deterministic
// and performs no I/O.
func (v *Verifier) VerifyProofList(ctx context.Context, pl prooflist.ProofList) (bool, error) {
	_ = ctx
	if v == nil || v.provider == nil {
		return false, fmt.Errorf("verifier backend provider is nil")
	}
	if err := pl.ValidateShape(prooflist.RequireSteps()); err != nil {
		return false, err
	}

	var verifiedPath proofListVerifiedPath
	for i, step := range pl.Steps {
		ok, err := v.verifyStep(i, step)
		if err != nil || !ok {
			return ok, err
		}
		if err := verifiedPath.addStep(step); err != nil {
			return false, err
		}
	}
	if err := validateProofListQuery(pl, verifiedPath); err != nil {
		return false, err
	}
	return true, nil
}

func (v *Verifier) verifyStep(index int, step prooflist.Step) (bool, error) {
	switch step.EvidenceKind {
	case "explicit":
		if step.Kind != prooflist.KindMapStep && step.Kind != prooflist.KindPayloadBinding {
			return false, fmt.Errorf("prooflist step %d explicit evidence does not match kind %q", index, step.Kind)
		}
		return v.verifyMapStep(index, step, structure.Proof(step.Evidence))
	case "implicit", "hamt":
		return false, fmt.Errorf("prooflist step %d uses legacy evidence kind %q; portable verifier supports explicit MALT evidence only", index, step.EvidenceKind)
	case "structure":
		switch step.EvidenceBackend {
		case "map":
			if step.Kind != prooflist.KindMapStep && step.Kind != prooflist.KindMapAbsence && step.Kind != prooflist.KindPayloadBinding {
				return false, fmt.Errorf("prooflist step %d structure/map evidence does not match kind %q", index, step.Kind)
			}
			return v.verifyMapStep(index, step, structure.Proof(step.Proof))
		case "list", "measured_list":
			lists, err := v.provider.listVerifier(step.From)
			if err != nil {
				return false, fmt.Errorf("prooflist step %d: %w", index, err)
			}
			return VerifyProofListListStructure(lists, step, index)
		default:
			return false, fmt.Errorf("prooflist step %d has unsupported structure evidence backend %q", index, step.EvidenceBackend)
		}
	default:
		return false, fmt.Errorf("prooflist step %d has unsupported evidence labels %q/%q", index, step.EvidenceKind, step.EvidenceBackend)
	}
}

func (v *Verifier) verifyMapStep(index int, step prooflist.Step, proof structure.Proof) (bool, error) {
	key := arcset.CanonicalizePath(step.Path)
	if key.IsEmpty() {
		return false, fmt.Errorf("prooflist step %d map path is empty", index)
	}
	maps, err := v.provider.mapVerifier(step.From)
	if err != nil {
		return false, fmt.Errorf("prooflist step %d: %w", index, err)
	}
	expected := mapping.Binding{Value: step.Target, Present: true}
	if step.Kind == prooflist.KindMapAbsence {
		if step.Target.Defined() {
			return false, fmt.Errorf("prooflist step %d map absence target is defined", index)
		}
		expected = mapping.Binding{Present: false}
	}
	return maps.Verify(step.From, key, expected, proof)
}

func validateProofListQuery(pl prooflist.ProofList, verifiedPath proofListVerifiedPath) error {
	// ProofList query labels live in semantic coordinate space. Transport and
	// layout adapters may apply their own path policy before constructing a
	// typed query, but the portable verifier must use the same canonical arc
	// coordinate rules as map creation and proof generation.
	want := arcset.CanonicalizePath(pl.Query).String()
	if want == "" {
		return nil
	}
	got := verifiedPath.logicalQueryPath()
	if got == want {
		return nil
	}
	// A root-relative typed list query has no map-path components. Bind its
	// public query label directly to the authenticated list coordinate rather
	// than treating it as a slash-separated map path.
	if got == "" {
		if typed, ok := typedListQuery(pl.Steps); ok && want == typed {
			return nil
		}
	}
	if verifiedPath.hasPayloadBinding {
		payloadQuery := arcset.PayloadPath.String()
		if got != "" {
			payloadQuery = got + "/@payload"
		}
		if want == payloadQuery {
			return nil
		}
	}
	return fmt.Errorf("prooflist query %q does not match ordered traversal path %q", want, got)
}

func typedListQuery(steps []prooflist.Step) (string, bool) {
	if len(steps) != 1 {
		return "", false
	}
	step := steps[0]
	switch step.Kind {
	case prooflist.KindListIndex:
		if step.Index == nil {
			return "", false
		}
		return fmt.Sprintf("list:%d", *step.Index), true
	case prooflist.KindListRange:
		if step.Start == nil {
			return "", false
		}
		end := ""
		if step.End != nil {
			end = fmt.Sprintf("%d", *step.End)
		}
		return fmt.Sprintf("range:%d:%s", *step.Start, end), true
	default:
		return "", false
	}
}

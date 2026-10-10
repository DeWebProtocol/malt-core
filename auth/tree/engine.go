// Package tree implements canonical authentication trees for one ArcSet.
// Coordinates select authenticated slots; Prefix leaves bind original label
// bytes and targets. Coordinate derivation is an injected pure capability;
// application interpretation, graph traversal and persistence belong to callers.
package tree

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"sync"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/coordinate"
	"github.com/dewebprotocol/malt-core/maltcid"
	cid "github.com/ipfs/go-cid"
)

// Profile identifies an installed implementation independently of its capabilities.
// A KZG/IPA algorithm name or vector capacity alone is not sufficient.
type Profile interface {
	MaxValues() int
	ProfileID() maltcid.ProfileID
}

type Registry struct {
	mu      sync.RWMutex
	schemes map[maltcid.ProfileID]Profile
}

func NewRegistry() *Registry { return &Registry{schemes: make(map[maltcid.ProfileID]Profile)} }
func (r *Registry) Register(s Profile) error {
	if r == nil || s == nil || (reflect.ValueOf(s).Kind() == reflect.Ptr && reflect.ValueOf(s).IsNil()) {
		return errors.New("profile registry and implementation are required")
	}
	p, err := maltcid.Profile(s.ProfileID())
	if err != nil {
		return err
	}
	if p.Slots != s.MaxValues() {
		return errors.New("implementation capacity does not match VC profile")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.schemes[p.ID]; exists {
		return fmt.Errorf("VC profile %d is already registered", p.ID)
	}
	if r.schemes == nil {
		r.schemes = make(map[maltcid.ProfileID]Profile)
	}
	r.schemes[p.ID] = s
	return nil
}
func (r *Registry) lookup(id maltcid.ProfileID) (Profile, error) {
	if r == nil {
		return nil, errors.New("profile registry is nil")
	}
	r.mu.RLock()
	s := r.schemes[id]
	r.mu.RUnlock()
	if s == nil {
		return nil, fmt.Errorf("VC profile %d is not installed", id)
	}
	return s, nil
}

// Deriver computes coordinates under the Root's derivation profile. It must be
// deterministic and must not normalize or reinterpret application label bytes.
type Deriver func(profile uint8, label []byte) (coordinate.Coordinate, error)

type Engine struct {
	Profiles *Registry
	derive   Deriver
}

func New(profiles *Registry, derive Deriver) *Engine {
	return &Engine{Profiles: profiles, derive: derive}
}

// ErrCoordinateCollision means distinct labels occupy the same full coordinate.
// Collisions are errors, never membership or authenticated absence.
var ErrCoordinateCollision = errors.New("distinct labels derive to the same authentication coordinate")

type binding struct {
	coordinate coordinate.Coordinate
	label      []byte
	target     cid.Cid
}

func (e *Engine) config(d maltcid.RootDescriptor) (Profile, maltcid.VCProfile, error) {
	if e == nil || e.derive == nil {
		return nil, maltcid.VCProfile{}, errors.New("authentication tree is not configured")
	}
	if err := d.Validate(); err != nil {
		return nil, maltcid.VCProfile{}, err
	}
	s, err := e.Profiles.lookup(d.Profile)
	if err != nil {
		return nil, maltcid.VCProfile{}, err
	}
	p, err := maltcid.Profile(d.Profile)
	return s, p, err
}

func (e *Engine) labelCoordinate(d maltcid.RootDescriptor, label []byte) (coordinate.Coordinate, error) {
	if label == nil {
		return coordinate.Coordinate{}, errors.New("label must be present; use an empty slice for an empty label")
	}
	k, err := e.derive(d.DerivationProfile, bytes.Clone(label))
	if err != nil {
		return coordinate.Coordinate{}, err
	}
	return checkCoordinate(d, k)
}

// Selector retains the original identity alongside its routing coordinate.
type Selector struct {
	Coordinate coordinate.Coordinate
	Label      []byte
}

func (e *Engine) selector(d maltcid.RootDescriptor, query Selector) (coordinate.Coordinate, error) {
	k, err := e.labelCoordinate(d, query.Label)
	if err != nil {
		return coordinate.Coordinate{}, err
	}
	if k != query.Coordinate {
		return coordinate.Coordinate{}, errors.New("label does not derive to the supplied coordinate")
	}
	return k, nil
}

// CheckDescriptor validates the full Root configuration and installed VC profile.
func (e *Engine) CheckDescriptor(d maltcid.RootDescriptor) error {
	_, _, err := e.config(d)
	return err
}
func checkCoordinate(d maltcid.RootDescriptor, k coordinate.Coordinate) (coordinate.Coordinate, error) {
	if d.Layout == maltcid.Prefix && (k.Kind != coordinate.Key || k.Index != 0) || d.Layout == maltcid.Positional && (k.Kind != coordinate.Index || k.Key != ([32]byte{})) {
		return coordinate.Coordinate{}, errors.New("invalid authentication coordinate")
	}
	return k, nil
}

// View carries routing coordinates and their authenticated original identities.
type View struct {
	Descriptor maltcid.RootDescriptor
	Bindings   []CoordinateBinding
	PayloadCID cid.Cid
}
type CoordinateBinding struct {
	Coordinate coordinate.Coordinate
	Label      []byte
	Target     cid.Cid
}

// Commit checks label-derived coordinates, constructs the layout, then wraps
// its commitment in the full self-describing Root. Native keys are not rehashed.
func (e *Engine) Commit(ctx context.Context, state View, out materializer.NodeUpdater) (cid.Cid, error) {
	s, p, err := e.config(state.Descriptor)
	if err != nil {
		return cid.Undef, err
	}
	committer, ok := s.(commitment.Committer)
	if !ok {
		return cid.Undef, errors.New("VC profile cannot compute commitments")
	}
	if out == nil {
		return cid.Undef, errors.New("node materializer is nil")
	}
	items := make([]binding, len(state.Bindings))
	for i, entry := range state.Bindings {
		if err := ctx.Err(); err != nil {
			return cid.Undef, err
		}
		k, err := e.selector(state.Descriptor, Selector{Coordinate: entry.Coordinate, Label: entry.Label})
		if err != nil {
			return cid.Undef, err
		}
		if !entry.Target.Defined() {
			return cid.Undef, errors.New("undefined binding target")
		}
		items[i] = binding{coordinate: k, label: bytes.Clone(entry.Label), target: entry.Target}
	}
	build := builder{registry: e.Profiles, ctx: ctx, descriptor: state.Descriptor, profile: p, scheme: committer, out: out}
	var ref maltcid.NodeRef
	if state.Descriptor.Layout == maltcid.Prefix {
		if state.PayloadCID.Defined() {
			return cid.Undef, errors.New("Prefix cannot carry sequence metadata")
		}
		sort.Slice(items, func(i, j int) bool { return bytes.Compare(items[i].coordinate.Key[:], items[j].coordinate.Key[:]) < 0 })
		for i := 1; i < len(items); i++ {
			if items[i-1].coordinate.Key == items[i].coordinate.Key {
				if !bytes.Equal(items[i-1].label, items[i].label) {
					return cid.Undef, ErrCoordinateCollision
				}
				return cid.Undef, errors.New("duplicate authentication label")
			}
		}
		ref, err = build.prefix(items, 0)
	} else {
		sort.Slice(items, func(i, j int) bool { return items[i].coordinate.Index < items[j].coordinate.Index })
		for i, item := range items {
			if item.coordinate.Index != uint64(i) {
				return cid.Undef, errors.New("Positional indices must be dense and unique")
			}
		}
		meta := Metadata{Count: uint64(len(items)), PayloadCID: state.PayloadCID}
		ref, err = build.positional(items, meta)
	}
	if err != nil {
		return cid.Undef, err
	}
	return maltcid.NewRoot(state.Descriptor, ref.Commitment)
}

type builder struct {
	registry   *Registry
	ctx        context.Context
	descriptor maltcid.RootDescriptor
	profile    maltcid.VCProfile
	scheme     commitment.Committer
	out        materializer.NodeUpdater
}

func (b *builder) commit(cells []commitment.Cell) (maltcid.NodeRef, error) {
	if err := b.ctx.Err(); err != nil {
		return maltcid.NodeRef{}, err
	}
	root, err := b.scheme.Commit(cells)
	if err != nil {
		return maltcid.NodeRef{}, err
	}
	c, err := root.CommitmentBytes(b.profile.ID)
	if err != nil {
		return maltcid.NodeRef{}, err
	}
	if root.ProfileID() != b.profile.ID {
		return maltcid.NodeRef{}, errors.New("commitment implementation returned the wrong profile algorithm")
	}
	ref := maltcid.NodeRef{Layout: b.descriptor.Layout, Profile: b.profile.ID, Commitment: c}
	if err := putComputed(b.ctx, b.out, ref, cells, b.registry); err != nil {
		return maltcid.NodeRef{}, err
	}
	return ref, nil
}

const (
	prefixLeaf     byte = maltcid.PrefixLeafCell
	childNode      byte = maltcid.ChildNodeCell
	positionalLeaf byte = maltcid.PositionalLeafCell
	metadataCell   byte = maltcid.MetadataCell
)

func childCell(ref maltcid.NodeRef) (commitment.Cell, error) {
	data, err := ref.Bytes()
	return append(commitment.Cell{childNode}, data...), err
}
func parseChild(cell commitment.Cell, expected maltcid.NodeRef) (maltcid.NodeRef, error) {
	if len(cell) < 2 || cell[0] != childNode {
		return maltcid.NodeRef{}, errors.New("expected internal node reference")
	}
	ref, err := maltcid.ParseNodeRef(cell[1:])
	if err != nil {
		return maltcid.NodeRef{}, err
	}
	if ref.Layout != expected.Layout || ref.Profile != expected.Profile {
		return maltcid.NodeRef{}, errors.New("mixed layout or VC profile inside authentication tree")
	}
	return ref, nil
}
func prefixCell(item binding) commitment.Cell {
	cell := binary.AppendUvarint(commitment.Cell{prefixLeaf}, uint64(len(item.label)))
	cell = append(cell, item.label...)
	return append(cell, item.target.Bytes()...)
}
func parsePrefix(cell commitment.Cell) ([]byte, cid.Cid, error) {
	if len(cell) < 3 || cell[0] != prefixLeaf {
		return nil, cid.Undef, errors.New("invalid Prefix leaf")
	}
	size, n := binary.Uvarint(cell[1:])
	if n <= 0 || n > 9 || len(binary.AppendUvarint(nil, size)) != n || size >= uint64(len(cell)-1-n) {
		return nil, cid.Undef, errors.New("invalid or noncanonical Prefix label length")
	}
	end := 1 + n + int(size)
	label := append([]byte{}, cell[1+n:end]...)
	target, err := cid.Cast(cell[end:])
	if err != nil {
		return nil, cid.Undef, err
	}
	if !bytes.Equal(target.Bytes(), cell[end:]) {
		return nil, cid.Undef, errors.New("noncanonical target")
	}
	return label, target, nil
}
func digit(key [32]byte, depth, slots int) (int, error) {
	bits := 0
	for n := slots; n > 1; n >>= 1 {
		bits++
	}
	if slots < 2 || 1<<bits != slots || depth < 0 || depth*bits >= 256 {
		return 0, errors.New("invalid Prefix geometry or depth")
	}
	value := 0
	for i := 0; i < bits; i++ {
		value <<= 1
		bit := depth*bits + i
		if bit < 256 {
			value |= int((key[bit/8] >> uint(7-bit%8)) & 1)
		}
	}
	return value, nil
}
func (b *builder) prefix(items []binding, depth int) (maltcid.NodeRef, error) {
	cells := make([]commitment.Cell, b.profile.Slots)
	groups := make(map[int][]binding)
	for _, item := range items {
		d, err := digit(item.coordinate.Key, depth, b.profile.Slots)
		if err != nil {
			return maltcid.NodeRef{}, err
		}
		groups[d] = append(groups[d], item)
	}
	// Deterministic traversal also makes materialization ordering reproducible.
	for i := range cells {
		group := groups[i]
		if len(group) == 1 {
			cells[i] = prefixCell(group[0])
		} else if len(group) > 1 {
			ref, err := b.prefix(group, depth+1)
			if err != nil {
				return maltcid.NodeRef{}, err
			}
			cells[i], err = childCell(ref)
			if err != nil {
				return maltcid.NodeRef{}, err
			}
		}
	}
	return b.commit(cells)
}

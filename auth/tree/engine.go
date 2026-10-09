// Package tree implements canonical authentication trees for one ArcSet.
// It consumes only derived coordinates and structural metadata. Input semantics,
// graph traversal, persistence and publication belong to its callers.
package tree

import (
	"bytes"
	"context"
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

type Engine struct{ Profiles *Registry }

func New(profiles *Registry) *Engine { return &Engine{Profiles: profiles} }

type binding struct {
	coordinate coordinate.Coordinate
	target     cid.Cid
}

func (e *Engine) config(d maltcid.RootDescriptor) (Profile, maltcid.VCProfile, error) {
	if e == nil {
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

// View is the authentication-coordinate boundary between input interpretation
// and layouts. Metadata is structural, and no application label is stored here.
type View struct {
	Descriptor maltcid.RootDescriptor
	Bindings   []CoordinateBinding
	PayloadCID cid.Cid
}
type CoordinateBinding struct {
	Coordinate coordinate.Coordinate
	Target     cid.Cid
}

// Commit consumes already-derived coordinates, constructs the layout, then
// wraps its commitment in the full self-describing Root. It never hashes a key.
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
		k := entry.Coordinate
		if !entry.Target.Defined() {
			return cid.Undef, errors.New("undefined binding target")
		}
		if state.Descriptor.Layout == maltcid.Prefix && (k.Kind != coordinate.Key || k.Index != 0) || state.Descriptor.Layout == maltcid.Positional && (k.Kind != coordinate.Index || k.Key != ([32]byte{})) {
			return cid.Undef, errors.New("invalid authentication coordinate")
		}
		items[i] = binding{coordinate: k, target: entry.Target}
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
				return cid.Undef, errors.New("duplicate authentication key, including canonical aliases")
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
	cell := append(commitment.Cell{prefixLeaf}, item.coordinate.Key[:]...)
	return append(cell, item.target.Bytes()...)
}
func parsePrefix(cell commitment.Cell) ([32]byte, cid.Cid, error) {
	if len(cell) <= 33 || cell[0] != prefixLeaf {
		return [32]byte{}, cid.Undef, errors.New("invalid Prefix leaf")
	}
	key := [32]byte(cell[1:33])
	target, err := cid.Cast(cell[33:])
	if err != nil {
		return key, cid.Undef, err
	}
	if !bytes.Equal(target.Bytes(), cell[33:]) {
		return key, cid.Undef, errors.New("noncanonical target")
	}
	return key, target, nil
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

// Package tree implements canonical authentication trees for one ArcSet.
// It consumes only derived coordinates and structural metadata. Input semantics,
// graph traversal, persistence and publication belong to its callers.
package tree

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"reflect"
	"sort"
	"sync"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/coordinate"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

// ProfileVerifier binds an implementation to an exact registered VC profile.
// A KZG/IPA algorithm name or vector capacity alone is not sufficient.
type ProfileVerifier interface {
	commitment.IndexVerifier
	ProfileID() maltcid.ProfileID
}

type Registry struct {
	mu      sync.RWMutex
	schemes map[maltcid.ProfileID]ProfileVerifier
}

func NewRegistry() *Registry { return &Registry{schemes: make(map[maltcid.ProfileID]ProfileVerifier)} }
func (r *Registry) Register(s ProfileVerifier) error {
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
		r.schemes = make(map[maltcid.ProfileID]ProfileVerifier)
	}
	r.schemes[p.ID] = s
	return nil
}
func (r *Registry) lookup(id maltcid.ProfileID) (ProfileVerifier, error) {
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
	coordinate coordinate.Value
	target     cid.Cid
}

func (e *Engine) config(d maltcid.RootDescriptor) (ProfileVerifier, maltcid.VCProfile, error) {
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
func checkCoordinate(d maltcid.RootDescriptor, k coordinate.Value) (coordinate.Value, error) {
	if d.Layout == maltcid.Prefix && (k.Kind != coordinate.Key || k.Index != 0) || d.Layout == maltcid.Positional && (k.Kind != coordinate.Index || k.Key != ([32]byte{})) {
		return coordinate.Value{}, errors.New("invalid authentication coordinate")
	}
	return k, nil
}

// View is the authentication-coordinate boundary between input interpretation
// and layouts. Metadata is structural, and no application label is stored here.
type View struct {
	Descriptor maltcid.RootDescriptor
	Bindings   []CoordinateBinding
	ChunkSize  uint64
	TotalSize  uint64
}
type CoordinateBinding struct {
	Coordinate coordinate.Value
	Target     cid.Cid
}

// Commit consumes already-derived coordinates, constructs the layout, then
// wraps its commitment in the full self-describing Root. It never hashes a key.
func (e *Engine) Commit(ctx context.Context, state View, out materializer.NodeUpdater) (cid.Cid, error) {
	s, p, err := e.config(state.Descriptor)
	if err != nil {
		return cid.Undef, err
	}
	prover, ok := s.(commitment.IndexProver)
	if !ok {
		return cid.Undef, errors.New("VC profile is verification-only")
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
	build := builder{registry: e.Profiles, ctx: ctx, descriptor: state.Descriptor, profile: p, scheme: prover, out: out}
	var ref maltcid.NodeRef
	if state.Descriptor.Layout == maltcid.Prefix {
		if state.ChunkSize != 0 || state.TotalSize != 0 {
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
		meta := Metadata{Count: uint64(len(items)), ChunkSize: state.ChunkSize, TotalSize: state.TotalSize}
		if err := meta.validate(); err != nil {
			return cid.Undef, err
		}
		meta.Height, err = height(meta.Count, uint64(p.Slots-1))
		if err != nil {
			return cid.Undef, err
		}
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
	scheme     commitment.IndexProver
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

// Metadata is structural sequence information. It contains no system binding.
type Metadata struct {
	Height    uint64 `json:"height,string"`
	Count     uint64 `json:"count,string"`
	ChunkSize uint64 `json:"chunk_size,string"`
	TotalSize uint64 `json:"total_size,string"`
}

func (m Metadata) validate() error {
	if m.ChunkSize == 0 {
		if m.TotalSize != 0 {
			return errors.New("plain sequence has a total byte size")
		}
		return nil
	}
	if m.Count == 0 {
		if m.TotalSize != 0 {
			return errors.New("empty measured sequence has content")
		}
		return nil
	}
	if m.Count-1 > math.MaxUint64/m.ChunkSize || m.TotalSize <= (m.Count-1)*m.ChunkSize || (m.TotalSize-1)/m.ChunkSize != m.Count-1 {
		return errors.New("measured size does not match chunk count")
	}
	return nil
}
func (m Metadata) cell() commitment.Cell {
	data := commitment.Cell{metadataCell}
	for _, v := range []uint64{m.Height, m.Count, m.ChunkSize, m.TotalSize} {
		data = binary.BigEndian.AppendUint64(data, v)
	}
	return data
}
func parseMetadata(data commitment.Cell) (Metadata, error) {
	if len(data) != 33 || data[0] != metadataCell {
		return Metadata{}, errors.New("invalid Positional metadata")
	}
	m := Metadata{binary.BigEndian.Uint64(data[1:9]), binary.BigEndian.Uint64(data[9:17]), binary.BigEndian.Uint64(data[17:25]), binary.BigEndian.Uint64(data[25:33])}
	return m, m.validate()
}
func height(count, branch uint64) (uint64, error) {
	if branch < 2 {
		return 0, errors.New("invalid Positional geometry")
	}
	h := uint64(0)
	capacity := branch
	for count > capacity {
		h++
		if capacity > math.MaxUint64/branch {
			return h, nil
		}
		capacity *= branch
	}
	return h, nil
}
func subtreeSpan(h, branch uint64) (uint64, error) {
	span := uint64(1)
	for i := uint64(0); i < h; i++ {
		if span > math.MaxUint64/branch {
			return 0, errors.New("Positional span overflow")
		}
		span *= branch
	}
	return span, nil
}
func (b *builder) positional(items []binding, meta Metadata) (maltcid.NodeRef, error) {
	cells := make([]commitment.Cell, b.profile.Slots)
	cells[0] = meta.cell()
	if meta.Height == 0 {
		for i, item := range items {
			cells[i+1] = append(commitment.Cell{positionalLeaf}, item.target.Bytes()...)
		}
		return b.commit(cells)
	}
	span, err := subtreeSpan(meta.Height, uint64(b.profile.Slots-1))
	if err != nil {
		return maltcid.NodeRef{}, err
	}
	for start, slot := uint64(0), 1; start < uint64(len(items)); start, slot = start+span, slot+1 {
		end := min(start+span, uint64(len(items)))
		child := meta
		child.Height--
		child.Count = end - start
		if meta.ChunkSize > 0 {
			remaining := meta.TotalSize - start*meta.ChunkSize
			child.TotalSize = remaining
			if child.Count <= remaining/meta.ChunkSize {
				child.TotalSize = child.Count * meta.ChunkSize
			}
		}
		ref, err := b.positional(items[start:end], child)
		if err != nil {
			return maltcid.NodeRef{}, err
		}
		cells[slot], err = childCell(ref)
		if err != nil {
			return maltcid.NodeRef{}, err
		}
	}
	return b.commit(cells)
}

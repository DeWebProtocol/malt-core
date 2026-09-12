// Package layoutcompat preserves Map/List convenience interfaces over the
// V=0 input/layout engine. New callers can use auth/engine's typed inputs and
// separate Interpret/Commit operations directly.
package layoutcompat

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	"github.com/dewebprotocol/malt-core/auth/arcset/materializer"
	"github.com/dewebprotocol/malt-core/auth/arcset/materializer/encoded"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/engine"
	"github.com/dewebprotocol/malt-core/auth/input"
	"github.com/dewebprotocol/malt-core/auth/observation"
	structure "github.com/dewebprotocol/malt-core/auth/semantic"
	"github.com/dewebprotocol/malt-core/auth/semantic/list"
	"github.com/dewebprotocol/malt-core/auth/semantic/mapping"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

func Engine(s commitment.IndexVerifier, rules *input.Registry) (*engine.Engine, maltcid.ProfileID, error) {
	profile, ok := s.(engine.ProfileVerifier)
	if !ok {
		return nil, 0, errors.New("V=0 requires an explicitly profiled VC implementation")
	}
	registry := engine.NewRegistry()
	if err := registry.Register(profile); err != nil {
		return nil, 0, err
	}
	if rules == nil {
		rules = input.DefaultRegistry()
	}
	return engine.New(rules, registry), profile.ProfileID(), nil
}

// PathInput is ONLY a compatibility projection for the old string API. The
// typed engine distinguishes literal label bytes from system selectors.
func PathInput(rule uint8, key arcset.Path) (input.Value, error) {
	if input.ID(rule) == input.Direct {
		raw, err := hex.DecodeString(key.String())
		if err != nil || len(raw) != 32 {
			return input.Value{}, errors.New("native-key convenience API requires 64 lowercase hex digits")
		}
		if hex.EncodeToString(raw) != key.String() {
			return input.Value{}, errors.New("noncanonical native key")
		}
		return input.KeyValue([32]byte(raw)), nil
	}
	if key == arcset.PayloadPath {
		return input.SystemValue(input.Payload), nil
	}
	return input.LabelValue([]byte(key)), nil
}

type Prefix struct {
	engine     *engine.Engine
	profile    maltcid.ProfileID
	rule       input.ID
	store      materializer.NodeStore
	commitment *mapping.Commitment
}

func NewPrefix(s commitment.IndexCommitment, store materializer.NodeStore, rules *input.Registry, rule input.ID) (*Prefix, error) {
	e, p, err := Engine(s, rules)
	if err != nil {
		return nil, err
	}
	c, err := mapping.NewCommitment(s)
	if err != nil {
		return nil, err
	}
	return &Prefix{e, p, rule, store, c}, nil
}
func (s *Prefix) Commitment() *mapping.Commitment { return s.commitment }
func (s *Prefix) nodes(scope string) encoded.Nodes {
	return encoded.Nodes{Lookup: s.store, Updater: s.store, Scope: scope}
}
func (s *Prefix) state(d maltcid.RootDescriptor, view mapping.View) (engine.State, error) {
	if view == nil {
		return engine.State{}, errors.New("map view is nil")
	}
	state := engine.State{Descriptor: d}
	it := view.Iterate()
	for {
		path, target, ok := it.Next()
		if !ok {
			break
		}
		v, err := PathInput(d.InputRule, path)
		if err != nil {
			return engine.State{}, err
		}
		state.Entries = append(state.Entries, engine.Entry{Input: v, Target: target})
	}
	if err := it.Err(); err != nil {
		return engine.State{}, err
	}
	if len(state.Entries) != view.Len() {
		return engine.State{}, errors.New("view length differs from iteration")
	}
	return state, nil
}
func (s *Prefix) Commit(ctx context.Context, scope string, view mapping.View) (cid.Cid, error) {
	state, err := s.state(maltcid.RootDescriptor{Layout: maltcid.Prefix, InputRule: uint8(s.rule), Profile: s.profile}, view)
	if err != nil {
		return cid.Undef, err
	}
	return s.engine.Build(ctx, state, s.nodes(scope))
}
func (s *Prefix) Prove(ctx context.Context, scope string, root cid.Cid, key arcset.Path) (mapping.Binding, structure.Proof, error) {
	d, _, err := maltcid.ParseRoot(root)
	if err != nil {
		return mapping.Binding{}, nil, err
	}
	if d.Layout != maltcid.Prefix {
		return mapping.Binding{}, nil, errors.New("not a Prefix root")
	}
	q, err := PathInput(d.InputRule, key)
	if err != nil {
		return mapping.Binding{}, nil, err
	}
	r, err := s.engine.Prove(ctx, root, q, s.nodes(scope))
	if err != nil {
		return mapping.Binding{}, nil, err
	}
	finishSerialization := observation.Start(ctx, observation.PhaseSerialization)
	proof, err := json.Marshal(r.Proof)
	finishSerialization(1, 1, uint64(len(proof)))
	return mapping.Binding{Present: r.Present, Value: r.Target}, proof, err
}
func VerifyPrefix(e *engine.Engine, root cid.Cid, key arcset.Path, expected mapping.Binding, proof structure.Proof) (bool, error) {
	d, _, err := maltcid.ParseRoot(root)
	if err != nil {
		return false, err
	}
	if d.Layout != maltcid.Prefix {
		return false, errors.New("not a Prefix root")
	}
	q, err := PathInput(d.InputRule, key)
	if err != nil {
		return false, err
	}
	result := engine.Result{Present: expected.Present, Target: expected.Value}
	if err := json.Unmarshal(proof, &result.Proof); err != nil {
		return false, err
	}
	return e.Verify(root, q, result)
}
func (s *Prefix) Verify(root cid.Cid, key arcset.Path, expected mapping.Binding, proof structure.Proof) (bool, error) {
	return VerifyPrefix(s.engine, root, key, expected, proof)
}
func (s *Prefix) Update(ctx context.Context, scope string, root cid.Cid, key arcset.Path, before, after cid.Cid) (cid.Cid, error) {
	return s.BatchUpdate(ctx, scope, root, []mapping.BatchUpdate{{Key: key, OldValue: before, NewValue: after}})
}
func (s *Prefix) BatchUpdate(ctx context.Context, scope string, root cid.Cid, updates []mapping.BatchUpdate) (cid.Cid, error) {
	d, _, err := maltcid.ParseRoot(root)
	if err != nil {
		return cid.Undef, err
	}
	if d.Layout != maltcid.Prefix {
		return cid.Undef, errors.New("not a Prefix root")
	}
	changes := make([]engine.Change, len(updates))
	for i, u := range updates {
		q, err := PathInput(d.InputRule, u.Key)
		if err != nil {
			return cid.Undef, err
		}
		changes[i] = engine.Change{Input: q, Before: u.OldValue, After: u.NewValue}
	}
	return s.engine.Apply(ctx, root, changes, s.nodes(scope), s.nodes(scope))
}

type Positional struct {
	engine     *engine.Engine
	profile    maltcid.ProfileID
	store      materializer.NodeStore
	commitment *list.Commitment
}

func NewPositional(s commitment.IndexCommitment, store materializer.NodeStore) (*Positional, error) {
	e, p, err := Engine(s, nil)
	if err != nil {
		return nil, err
	}
	c, err := list.NewCommitment(s)
	if err != nil {
		return nil, err
	}
	return &Positional{e, p, store, c}, nil
}
func (s *Positional) Commitment() *list.Commitment { return s.commitment }
func (s *Positional) nodes(scope string) encoded.Nodes {
	return encoded.Nodes{Lookup: s.store, Updater: s.store, Scope: scope}
}
func (s *Positional) Commit(ctx context.Context, scope string, view list.View) (cid.Cid, error) {
	if view == nil {
		return cid.Undef, errors.New("list view is nil")
	}
	state := engine.State{Descriptor: maltcid.RootDescriptor{Layout: maltcid.Positional, Profile: s.profile}}
	for i := uint64(0); i < view.Len(); i++ {
		v, ok := view.Get(i)
		if !ok {
			return cid.Undef, fmt.Errorf("missing position %d", i)
		}
		state.Entries = append(state.Entries, engine.Entry{Input: input.IndexValue(i), Target: v})
	}
	return s.engine.Build(ctx, state, s.nodes(scope))
}
func (s *Positional) CommitFixed(ctx context.Context, scope string, values []cid.Cid, chunkSize, totalSize uint64) (cid.Cid, error) {
	if chunkSize == 0 {
		return cid.Undef, errors.New("chunk size must be positive")
	}
	state := engine.State{Descriptor: maltcid.RootDescriptor{Layout: maltcid.Positional, Profile: s.profile}, ChunkSize: chunkSize, TotalSize: totalSize}
	for i, v := range values {
		state.Entries = append(state.Entries, engine.Entry{Input: input.IndexValue(uint64(i)), Target: v})
	}
	return s.engine.Build(ctx, state, s.nodes(scope))
}
func (s *Positional) Prove(ctx context.Context, scope string, root cid.Cid, index uint64) (list.Query, structure.Proof, error) {
	r, err := s.engine.Prove(ctx, root, input.IndexValue(index), s.nodes(scope))
	if err != nil {
		return list.Query{}, nil, err
	}
	meta, err := r.Proof.RootMetadata()
	if err != nil {
		return list.Query{}, nil, err
	}
	finishSerialization := observation.Start(ctx, observation.PhaseSerialization)
	proof, err := json.Marshal(r.Proof)
	finishSerialization(1, 1, uint64(len(proof)))
	return list.Query{Key: r.Target, Length: meta.Count}, proof, err
}
func VerifyPositional(e *engine.Engine, root cid.Cid, index uint64, expected list.Query, proof structure.Proof) (bool, error) {
	r := engine.Result{Present: expected.Key.Defined(), Target: expected.Key}
	if err := json.Unmarshal(proof, &r.Proof); err != nil {
		return false, err
	}
	meta, err := r.Proof.RootMetadata()
	if err != nil {
		return false, err
	}
	if meta.Count != expected.Length {
		return false, nil
	}
	return e.Verify(root, input.IndexValue(index), r)
}
func (s *Positional) Verify(root cid.Cid, index uint64, expected list.Query, proof structure.Proof) (bool, error) {
	return VerifyPositional(s.engine, root, index, expected, proof)
}
func (s *Positional) Replace(ctx context.Context, scope string, root cid.Cid, index uint64, before, after cid.Cid) (cid.Cid, error) {
	if !before.Defined() || !after.Defined() {
		return cid.Undef, errors.New("replace requires two defined targets")
	}
	return s.engine.Apply(ctx, root, []engine.Change{{Input: input.IndexValue(index), Before: before, After: after}}, s.nodes(scope), s.nodes(scope))
}
func (s *Positional) Append(ctx context.Context, scope string, root cid.Cid, target cid.Cid) (cid.Cid, uint64, error) {
	return s.engine.Append(ctx, root, target, nil, s.nodes(scope), s.nodes(scope))
}
func (s *Positional) AppendFixed(ctx context.Context, scope string, root cid.Cid, target cid.Cid, totalSize uint64) (cid.Cid, uint64, error) {
	next, index, err := s.engine.Append(ctx, root, target, &totalSize, s.nodes(scope), s.nodes(scope))
	if errors.Is(err, engine.ErrNotMeasured) {
		err = list.ErrNotMeasured
	}
	return next, index, err
}
func (s *Positional) Truncate(ctx context.Context, scope string, root cid.Cid, count uint64) (cid.Cid, error) {
	return s.engine.Truncate(ctx, root, count, s.nodes(scope), s.nodes(scope))
}
func (s *Positional) ProveRange(ctx context.Context, scope string, root cid.Cid, start uint64, end *uint64) (list.RangeResult, structure.Proof, error) {
	r, err := s.engine.ProveRange(ctx, root, start, end, s.nodes(scope))
	if errors.Is(err, engine.ErrNotMeasured) {
		return list.RangeResult{}, nil, list.ErrNotMeasured
	}
	if err != nil {
		return list.RangeResult{}, nil, err
	}
	out := list.RangeResult{Metadata: list.RangeMetadata{ChildCount: r.Metadata.Count, TotalSize: r.Metadata.TotalSize, ChunkSize: r.Metadata.ChunkSize}, Segments: []cid.Cid{}}
	for _, segment := range r.Segments {
		out.Segments = append(out.Segments, segment.Target)
	}
	finishSerialization := observation.Start(ctx, observation.PhaseSerialization)
	proof, err := json.Marshal(r)
	finishSerialization(1, 1, uint64(len(proof)))
	return out, proof, err
}
func VerifyRange(e *engine.Engine, root cid.Cid, start uint64, end *uint64, expected list.RangeResult, proof structure.Proof) (bool, error) {
	var r engine.RangeResult
	if err := json.Unmarshal(proof, &r); err != nil {
		return false, err
	}
	if expected.Metadata != (list.RangeMetadata{ChildCount: r.Metadata.Count, TotalSize: r.Metadata.TotalSize, ChunkSize: r.Metadata.ChunkSize}) || len(expected.Segments) != len(r.Segments) {
		return false, nil
	}
	for i, v := range expected.Segments {
		if !v.Equals(r.Segments[i].Target) {
			return false, nil
		}
	}
	return e.VerifyRange(root, start, end, r)
}
func (s *Positional) VerifyRange(root cid.Cid, start uint64, end *uint64, expected list.RangeResult, proof structure.Proof) (bool, error) {
	return VerifyRange(s.engine, root, start, end, expected, proof)
}

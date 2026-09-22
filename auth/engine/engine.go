// Package engine binds typed application inputs to the coordinate-only authentication tree.
package engine

import (
	"context"
	"errors"
	"fmt"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer"
	"github.com/dewebprotocol/malt-core/auth/input"
	"github.com/dewebprotocol/malt-core/auth/tree"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

// These are the tree's shared types, also exposed by the typed-input facade.
type (
	Profile           = tree.Profile
	Registry          = tree.Registry
	View              = tree.View
	CoordinateBinding = tree.CoordinateBinding
	Metadata          = tree.Metadata
	Proof             = tree.Proof
	NodeOpening       = tree.NodeOpening
	Result            = tree.Result
	RangeResult       = tree.RangeResult
	DiscardNodes      = tree.DiscardNodes
)

const ProofFormat = tree.ProofFormat

var ErrNotMeasured = tree.ErrNotMeasured

func NewRegistry() *Registry { return tree.NewRegistry() }

type Engine struct {
	Rules *input.Registry
	Tree  *tree.Engine
}

func New(rules *input.Registry, profiles *Registry) *Engine {
	return &Engine{Rules: rules, Tree: tree.New(profiles)}
}
func (e *Engine) check(d maltcid.RootDescriptor) error {
	if e == nil || e.Rules == nil || e.Tree == nil {
		return errors.New("authentication engine is not configured")
	}
	if !e.Rules.Supports(input.ID(d.InputRule)) {
		return fmt.Errorf("unsupported input rule %d", d.InputRule)
	}
	return e.Tree.CheckDescriptor(d)
}

// CheckRoot checks the complete configuration, including the installed input rule.
func (e *Engine) CheckRoot(root cid.Cid) error {
	d, _, err := maltcid.ParseRoot(root)
	if err != nil {
		return err
	}
	return e.check(d)
}

type Entry struct {
	Input  input.Value `json:"input"`
	Target cid.Cid     `json:"target"`
}

// State stores the original inputs so label-based persistence can reconstruct
// a Root without pretending that labels and authentication keys are identical.
// ChunkSize/TotalSize are zero for Prefix and for plain Positional state.
type State struct {
	Descriptor maltcid.RootDescriptor `json:"descriptor"`
	Entries    []Entry                `json:"entries" schema:"optional,nullable"`
	ChunkSize  uint64                 `json:"chunk_size,omitempty,string"`
	TotalSize  uint64                 `json:"total_size,omitempty,string"`
}

func (e *Engine) coordinate(d maltcid.RootDescriptor, value input.Value) (input.Coordinate, error) {
	k, err := e.Rules.Derive(input.ID(d.InputRule), value)
	if err != nil {
		return input.Coordinate{}, err
	}
	if d.Layout == maltcid.Prefix && k.Kind != input.Key || d.Layout == maltcid.Positional && k.Kind != input.Index {
		return input.Coordinate{}, errors.New("input coordinate does not match layout")
	}
	return k, nil
}

// Interpret performs AA conversion without invoking a commitment primitive.
func (e *Engine) Interpret(state State) (View, error) {
	if err := e.check(state.Descriptor); err != nil {
		return View{}, err
	}
	view := View{Descriptor: state.Descriptor, ChunkSize: state.ChunkSize, TotalSize: state.TotalSize, Bindings: make([]CoordinateBinding, len(state.Entries))}
	for i, entry := range state.Entries {
		coordinate, err := e.coordinate(state.Descriptor, entry.Input)
		if err != nil {
			return View{}, fmt.Errorf("entry %d: %w", i, err)
		}
		view.Bindings[i] = CoordinateBinding{Coordinate: coordinate, Target: entry.Target}
	}
	return view, nil
}

// Build interprets application inputs and commits the resulting view. It
// creates a candidate only: it neither publishes nor accepts that Root.
func (e *Engine) Build(ctx context.Context, state State, out materializer.NodeUpdater) (cid.Cid, error) {
	view, err := e.Interpret(state)
	if err != nil {
		return cid.Undef, err
	}
	return e.Commit(ctx, view, out)
}

func (e *Engine) Commit(ctx context.Context, view View, out materializer.NodeUpdater) (cid.Cid, error) {
	if err := e.check(view.Descriptor); err != nil {
		return cid.Undef, err
	}
	return e.Tree.Commit(ctx, view, out)
}

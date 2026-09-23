// Package engine binds application labels to the coordinate-only authentication tree.
package engine

import (
	"context"
	"errors"
	"fmt"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer"
	"github.com/dewebprotocol/malt-core/auth/coordinate"
	"github.com/dewebprotocol/malt-core/auth/tree"
	"github.com/dewebprotocol/malt-core/derivation"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

// These are the tree's shared types, also exposed by the label-aware composition layer.
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
	Tree *tree.Engine
}

func New(profiles *Registry) *Engine {
	return &Engine{Tree: tree.New(profiles)}
}
func (e *Engine) check(d maltcid.RootDescriptor) error {
	if e == nil || e.Tree == nil {
		return errors.New("authentication engine is not configured")
	}
	if !derivation.Supported(derivation.ProfileID(d.DerivationProfile)) {
		return fmt.Errorf("unsupported coordinate derivation profile %d", d.DerivationProfile)
	}
	if d.Layout == maltcid.Positional && d.DerivationProfile != uint8(derivation.Direct) {
		return errors.New("Positional requires Direct derivation")
	}
	return e.Tree.CheckDescriptor(d)
}

// CheckRoot checks the complete configuration, including the installed coordinate derivation profile.
func (e *Engine) CheckRoot(root cid.Cid) error {
	d, _, err := maltcid.ParseRoot(root)
	if err != nil {
		return err
	}
	return e.check(d)
}

type Entry struct {
	Label  []byte  `json:"label"`
	Target cid.Cid `json:"target"`
}

// State stores the original labels so label-based persistence can reconstruct
// a Root without pretending that labels and authentication keys are identical.
// ChunkSize/TotalSize are zero for Prefix and for plain Positional state.
type State struct {
	Descriptor maltcid.RootDescriptor `json:"descriptor"`
	Entries    []Entry                `json:"entries" schema:"optional,nullable"`
	ChunkSize  uint64                 `json:"chunk_size,omitempty,string"`
	TotalSize  uint64                 `json:"total_size,omitempty,string"`
}

func (e *Engine) coordinate(d maltcid.RootDescriptor, value []byte) (coordinate.Coordinate, error) {
	if value == nil {
		return coordinate.Coordinate{}, errors.New("label must be present; use an empty slice for an empty label")
	}
	k, err := derivation.Derive(derivation.ProfileID(d.DerivationProfile), value)
	if err != nil {
		return coordinate.Coordinate{}, err
	}
	if d.Layout == maltcid.Prefix && k.Kind != coordinate.Key || d.Layout == maltcid.Positional && k.Kind != coordinate.Index {
		return coordinate.Coordinate{}, errors.New("derived coordinate does not match layout")
	}
	return k, nil
}

// Interpret derives coordinates from labels without invoking a commitment primitive.
func (e *Engine) Interpret(state State) (View, error) {
	if err := e.check(state.Descriptor); err != nil {
		return View{}, err
	}
	view := View{Descriptor: state.Descriptor, ChunkSize: state.ChunkSize, TotalSize: state.TotalSize, Bindings: make([]CoordinateBinding, len(state.Entries))}
	for i, entry := range state.Entries {
		coordinate, err := e.coordinate(state.Descriptor, entry.Label)
		if err != nil {
			return View{}, fmt.Errorf("entry %d: %w", i, err)
		}
		view.Bindings[i] = CoordinateBinding{Coordinate: coordinate, Target: entry.Target}
	}
	return view, nil
}

// Build interprets application labels and commits the resulting view. It
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

// Package runtimegraph composes core resolve, read, and mutation algorithms
// over an injected ArcSet materializer. It owns no persistence implementation,
// authoritative head, transport, or freshness policy.
package runtimegraph

import (
	"context"
	"fmt"

	malt "github.com/dewebprotocol/malt-core"
	materializer "github.com/dewebprotocol/malt-core/auth/arcset/materializer"
	"github.com/dewebprotocol/malt-core/auth/arcset/materializer/encoded"
	"github.com/dewebprotocol/malt-core/auth/engine"
	"github.com/dewebprotocol/malt-core/auth/input"
	"github.com/dewebprotocol/malt-core/auth/proof/prooflist"
	"github.com/dewebprotocol/malt-core/auth/semantic/layoutcompat"
	"github.com/dewebprotocol/malt-core/auth/semantic/list"
	listtree "github.com/dewebprotocol/malt-core/auth/semantic/list/tree"
	"github.com/dewebprotocol/malt-core/auth/semantic/mapping"
	mappingradix "github.com/dewebprotocol/malt-core/auth/semantic/mapping/radix"
	"github.com/dewebprotocol/malt-core/graph"
	"github.com/dewebprotocol/malt-core/graph/resolver"
	"github.com/dewebprotocol/malt-core/graph/resolver/step/explicit"
	"github.com/dewebprotocol/malt-core/graph/writer"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

// RuntimeGraph is a per-graph runtime composition of semantic implementations,
// resolver, and writer. It does not own authoritative heads or freshness policy.
// The root CID is always supplied by callers.
type RuntimeGraph struct {
	authentication *engine.Engine
	nodeStore      materializer.NodeStore
	id             string
	namespace      string
	semantic       mapping.Semantics
	listSemantic   list.Semantics
	resolver       graph.Resolver
	wr             graph.MutationWriter
	structures     graph.StructureCreator
}

// NewGraph creates a new per-graph instance with its own semantic layer,
// resolver, and writer.
//
// Parameters:
//   - id: unique graph identifier
//   - materializer: caller-owned ArcSet materializer
//   - opts: functional options (WithCommitmentScheme, WithNamespace, etc.)
func NewGraph(id string, materializer materializer.MutableStore, opts ...Option) (*RuntimeGraph, error) {
	o := defaultOptions()
	for _, opt := range opts {
		opt(o)
	}

	// Default namespace = graph id
	namespace := o.Namespace
	if namespace == "" {
		namespace = id
	}

	profiles := engine.NewRegistry()
	rules := o.InputRules
	if rules == nil {
		rules = input.DefaultRegistry()
	}
	var semantic mapping.Semantics
	var listSemantic list.Semantics
	if len(o.Backends) > 0 || o.DefaultBackend != "" {
		defaultBackend, err := validateBackendOptions(o)
		if err != nil {
			return nil, err
		}
		maps := make(map[maltcid.BackendKind]mapping.Semantics, len(o.Backends))
		lists := make(map[maltcid.BackendKind]list.MeasuredSemantics, len(o.Backends))
		for kind, scheme := range o.Backends {
			{
				profile, ok := scheme.(engine.ProfileVerifier)
				if !ok {
					return nil, fmt.Errorf("unprofiled VC implementation")
				}
				if err := profiles.Register(profile); err != nil {
					return nil, err
				}
			}
			maps[kind], err = mappingradix.NewMap(scheme, materializer)
			if err != nil {
				return nil, fmt.Errorf("create %s mapping semantic: %w", kind, err)
			}
			lists[kind], err = listtree.NewList(scheme, materializer)
			if err != nil {
				return nil, fmt.Errorf("create %s list semantic: %w", kind, err)
			}
		}
		semantic = &mapBackendDispatcher{defaultBackend: defaultBackend, backends: maps}
		listSemantic = &listBackendDispatcher{defaultBackend: defaultBackend, backends: lists}
	} else {
		// Default commitment scheme: KZG.
		scheme := o.Scheme
		if scheme == nil {
			s, err := newDefaultCommitmentScheme()
			if err != nil {
				return nil, fmt.Errorf("failed to create default KZG scheme: %w", err)
			}
			scheme = s
		}

		{
			profile, ok := scheme.(engine.ProfileVerifier)
			if !ok {
				return nil, fmt.Errorf("unprofiled VC implementation")
			}
			if err := profiles.Register(profile); err != nil {
				return nil, err
			}
		}
		var err error
		semantic, err = mappingradix.NewMap(scheme, materializer)
		if err != nil {
			return nil, fmt.Errorf("failed to create mapping semantic: %w", err)
		}
		listSemantic, err = listtree.NewList(scheme, materializer)
		if err != nil {
			return nil, fmt.Errorf("failed to create list semantic: %w", err)
		}
	}

	// Create per-graph explicit resolver
	explicitStep := explicit.NewResolver(materializer, semantic, namespace)

	// Create per-graph resolver with explicit native MALT resolution.
	res := resolver.NewResolver(explicitStep)

	// Create per-graph writer
	wr := writer.NewWriter(semantic, materializer, listSemantic)

	return &RuntimeGraph{
		authentication: engine.New(rules, profiles),
		nodeStore:      materializer,
		id:             id,
		namespace:      namespace,
		semantic:       semantic,
		listSemantic:   listSemantic,
		resolver:       res,
		wr:             wr,
		structures:     wr,
	}, nil
}

// ID returns the graph identifier.
func (g *RuntimeGraph) ID() string {
	return g.id
}

// Namespace returns the ArcSet materializer namespace for this graph.
func (g *RuntimeGraph) Namespace() string {
	return g.namespace
}

// Semantic returns the per-graph keyed-map semantic.
func (g *RuntimeGraph) Semantic() mapping.Semantics {
	return g.semantic
}

// ListSemantic returns the per-graph list semantic.
func (g *RuntimeGraph) ListSemantic() list.Semantics {
	return g.listSemantic
}

// Resolver returns the per-graph resolver.
func (g *RuntimeGraph) Resolver() graph.Resolver {
	return g.resolver
}

// Resolve adapts the reference graph resolver transcript to the portable core
// result consumed by execution.Executor and malt.VerifyResolve.
func (g *RuntimeGraph) Resolve(ctx context.Context, req malt.ResolveRequest) (malt.ResolveResult, error) {
	if g == nil {
		return malt.ResolveResult{}, fmt.Errorf("runtime graph is nil")
	}
	if err := req.Validate(); err != nil {
		return malt.ResolveResult{}, err
	}
	path, _ := malt.NewSegmentPath(req.Segments)
	if path.Empty() {
		return malt.ResolveResult{
			Target:    req.Root,
			ProofList: prooflist.ProofList{Root: req.Root, Query: "", Steps: []prooflist.Step{}},
		}, nil
	}
	resolved, err := g.resolver.ResolveKey(ctx, req.Root, path.String())
	if err != nil {
		return malt.ResolveResult{}, err
	}
	if resolved == nil || !resolved.RemainingPath.IsEmpty() || !resolved.Target.Defined() {
		return malt.ResolveResult{}, malt.ErrQueryNotFound
	}
	pl, err := resolver.ProofListFromTranscript(req.Root, resolved.Transcript)
	if err != nil {
		return malt.ResolveResult{}, err
	}
	pl.Query = path.String()
	return malt.ResolveResult{Target: resolved.Target, ProofList: *pl}, nil
}

// Writer returns the stable semantic-mutation capability. It intentionally
// omits legacy root-consuming helpers and reference inspection methods.
func (g *RuntimeGraph) Writer() graph.MutationWriter {
	return g.wr
}

// StructureCreator returns the separate bootstrap capability used to create a
// structure when there is no authenticated base root to mutate.
func (g *RuntimeGraph) StructureCreator() graph.StructureCreator {
	return g.structures
}

// Authentication exposes the V=0 input/layout engine. Callers inject narrow
// NodeLookup/NodeUpdater capabilities and retain application inputs themselves.
func (g *RuntimeGraph) Authentication() *engine.Engine { return g.authentication }

// CommitPrefix preserves the complete descriptor when rebuilding an existing
// Prefix through the compatibility string-view API. Native typed callers use
// Authentication().Build with input.Value entries directly.
func (g *RuntimeGraph) CommitPrefix(ctx context.Context, scope string, d maltcid.RootDescriptor, view mapping.View) (cid.Cid, error) {
	if d.Layout != maltcid.Prefix {
		return cid.Undef, fmt.Errorf("Prefix descriptor requires V=0 graph")
	}
	state := engine.State{Descriptor: d}
	it := view.Iterate()
	for {
		key, target, ok := it.Next()
		if !ok {
			break
		}
		value, err := layoutcompat.PathInput(d.InputRule, key)
		if err != nil {
			return cid.Undef, err
		}
		state.Entries = append(state.Entries, engine.Entry{Input: value, Target: target})
	}
	if err := it.Err(); err != nil {
		return cid.Undef, err
	}
	return g.authentication.Build(ctx, state, encoded.Nodes{Lookup: g.nodeStore, Updater: g.nodeStore, Scope: scope})
}
func (g *RuntimeGraph) RootVersion() uint8 { return maltcid.RootVersion }

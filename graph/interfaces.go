package graph

import (
	"context"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	"github.com/dewebprotocol/malt-core/graph/resolver"
	"github.com/dewebprotocol/malt-core/graph/writer"
	"github.com/dewebprotocol/malt-core/mutation"
	cid "github.com/ipfs/go-cid"
)

// Resolver is the graph read/proof port.
type Resolver interface {
	// ResolveKey traverses explicit authenticated relations without assuming a
	// payload coordinate. It is the generic graph-data authentication port.
	ResolveKey(ctx context.Context, root cid.Cid, path string) (*resolver.ResolveResult, error)
	// Resolve retains the reference materialization behavior that follows a
	// terminal @payload binding on map roots.
	Resolve(ctx context.Context, root cid.Cid, path string) (*resolver.ResolveResult, error)
	VerifyTranscript(ctx context.Context, root cid.Cid, transcript *resolver.Transcript) (bool, error)
}

// MutationWriter is the stable graph mutation port. Callers supply an explicit
// base root through mutation.SemanticMutation and receive a result root in the
// write receipt; this interface does not publish heads or arbitrate freshness.
type MutationWriter interface {
	Apply(ctx context.Context, namespace string, mut mutation.SemanticMutation) (mutation.WriteReceipt, error)
}

// StructureCreator bootstraps a semantic structure without claiming that the
// operation is an update from an already authenticated base root.
type StructureCreator interface {
	CreateStructure(ctx context.Context, namespace string, arcs arcset.ArcSet) (cid.Cid, error)
}

// ReferenceWriter exposes legacy root-consuming and inspection helpers used by
// reference executors and conformance tests. New integrations should depend on
// MutationWriter and, when required, the separate StructureCreator capability.
type ReferenceWriter interface {
	StructureCreator
	UpdateArc(ctx context.Context, namespace string, root cid.Cid, path string, newTarget cid.Cid) (*writer.UpdateResult, error)
	BatchUpdateArcs(ctx context.Context, namespace string, root cid.Cid, updates map[string]cid.Cid) (*writer.BatchUpdateResult, error)
	GetArc(ctx context.Context, namespace string, root cid.Cid, path string) (cid.Cid, error)
	GetSnapshot(ctx context.Context, namespace string, root cid.Cid) (arcset.ArcSet, error)
}

// CompatWriter is retained as a source-compatible alias for ReferenceWriter.
// Deprecated: use ReferenceWriter or a narrower capability.
type CompatWriter = ReferenceWriter

// Writer is the complete reference-runtime write surface.
// Deprecated: depend on MutationWriter, StructureCreator, or ReferenceWriter.
type Writer interface {
	MutationWriter
	ReferenceWriter
}

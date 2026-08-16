package runtimegraph

import (
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
)

// Option configures a Graph instance.
type Option func(*Options)

// Options holds configuration for Graph creation.
type Options struct {
	Scheme         commitment.IndexCommitment
	Backends       map[maltcid.BackendKind]commitment.IndexCommitment
	DefaultBackend maltcid.BackendKind
	Namespace      string
	MALTVersion    uint8
}

func defaultOptions() *Options {
	return &Options{
		Backends:    make(map[maltcid.BackendKind]commitment.IndexCommitment),
		MALTVersion: maltcid.MALTVersionID,
	}
}

// WithCommitmentScheme sets the commitment scheme for this Graph.
// Default: KZG.
func WithCommitmentScheme(scheme commitment.IndexCommitment) Option {
	return func(o *Options) {
		o.Scheme = scheme
	}
}

// WithCommitmentBackend registers one execution backend for typed-root
// dispatch. Existing-root operations select a registered backend from the
// root CID; use [WithDefaultCommitmentBackend] for operations that create a
// structure without an existing root.
func WithCommitmentBackend(kind maltcid.BackendKind, scheme commitment.IndexCommitment) Option {
	return func(o *Options) {
		if o.Backends == nil {
			o.Backends = make(map[maltcid.BackendKind]commitment.IndexCommitment)
		}
		o.Backends[kind] = scheme
	}
}

// WithDefaultCommitmentBackend selects the registered backend used only when
// an operation creates a structure without an existing typed root. It never
// overrides the backend encoded by an existing root CID.
func WithDefaultCommitmentBackend(kind maltcid.BackendKind) Option {
	return func(o *Options) {
		o.DefaultBackend = kind
	}
}

// WithMALTVersion selects the typed-root version emitted by map/list commits.
// It exists for exact replay of supported legacy complete views; new graphs
// should use the default current version.
func WithMALTVersion(version uint8) Option {
	return func(o *Options) {
		o.MALTVersion = version
	}
}

// WithNamespace sets the ArcSet materializer namespace for this Graph.
// Default: the graph's ID.
func WithNamespace(id string) Option {
	return func(o *Options) {
		o.Namespace = id
	}
}
